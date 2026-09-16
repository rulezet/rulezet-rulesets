rule sig_20160314_9a7c4ed67b8be724c65b5b0e21e60b67 {
  meta:
    description = "datamaliciousorder - file 20160314_9a7c4ed67b8be724c65b5b0e21e60b67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfa6400c3361206487c472d92a3813aaae6cc85dad526590ca0a002840c2ef5a"

  strings:
    $s1 = "while (SiC.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return VRI + WRfw + VKQLdOXAcufsZK + RiVpCMZZvRNdud + OiVsxTNMqNt + GAZOHKy + ZwXnABRyvItZa" fullword ascii
    $s3 = " YaPc + FTd + VCI + ztlkYgGyxqu + IStKJVDfh, false);" fullword ascii
    $s4 = "SiC.open(RaSJ + uRjJLfKP, MKGYKUNo + QnNwxYfzKdqCinb + ImBctjCatnSnWn + xeMZbSJdqgCSE + kKAWtWvqHY + CpTXXQeiTzw + RzSxtlWlUeF +" ascii
    $s5 = "function QFsVsmwhVWFSPKw(n)" fullword ascii
    $s6 = "var ovddELcjnJXbyel = new Date();" fullword ascii
    $s7 = "function cehBVOlNdrs(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}