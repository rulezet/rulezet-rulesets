rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aqOJzSd_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqOJzSd_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68074b9d8654f3cf558eb59fe0f9284382194257ba6eb8d1b1dc4609902e0e8e"

  strings:
    $s1  = " /t nearshipe  /c$lede /te" fullword ascii
    $s2  = "ickemaths boe get rane ateew nan rm dockni" fullword ascii
    $s3  = "wnDoadlog inw neaiemtel lamp." fullword ascii
    $s4  = "utshths coe utmp dern" fullword ascii
    $s5  = "ret nearshade n$mide /teley" fullword ascii
    $s6  = "3.rvSeeCiclHtrdlan(uerliti.cty):ppin Fheishad lend" fullword ascii
    $s7  = "erCSceviCS::vier(uceliti.cty):ppta SSerticrvtreCislDtcpar(he S):vier aceealr rdyniun." fullword ascii
    $s8  = "wndoadloans ma e lilt" fullword ascii
    $s9  = "mores vee tht bo iifdod  nes motchat" fullword ascii
    $s10 = "inpr atsis loft ll ava c" fullword ascii
    $s11 = "gnsi salp to ctoldhihr tdsea" fullword ascii
    $s12 = "kemaths boe pat  artha celnn" fullword ascii
    $s13 = "gilo:.n" fullword ascii
    $s14 = "s\" p-[cero lsst is" fullword ascii
    $s15 = "saDie blelshhal lend" fullword ascii
    $s16 = "gilo:!n" fullword ascii
    $s17 = "gilo:~n" fullword ascii
    $s18 = "exunFo2 d pico, esitexg.in" fullword ascii
    $s19 = "DEMOs  % %%s" fullword ascii
    $s20 = " (nncotiec tone:yp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}