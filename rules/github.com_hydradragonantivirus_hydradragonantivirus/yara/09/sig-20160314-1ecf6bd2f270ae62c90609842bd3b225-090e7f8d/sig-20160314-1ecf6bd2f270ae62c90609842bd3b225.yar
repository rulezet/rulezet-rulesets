rule sig_20160314_1ecf6bd2f270ae62c90609842bd3b225 {
  meta:
    description = "datamaliciousorder - file 20160314_1ecf6bd2f270ae62c90609842bd3b225.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50bf396888988b9e170f48e9e84ba2e4e9438040a864cb5a226ca7d08f88ac15"

  strings:
    $s1 = "while (HcbUQcw.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return FHQNQWSOvDVv + bMhj + XgkXWhOHiYo + ouneuZ + EFbVD + hQZLnkX + tKpDMOOmhBrnCwe + iCMHaTyfUe" fullword ascii
    $s3 = "HcbUQcw.open(ERswCGsuqwwCwv + xvzaIWN, eCsOJK + OFXHDlJm + abGUHBiAGTr + IHQ + KvERVSuAkkE + xApFUZRiwdReMd + kCnqxjF + lyBjIzpN" ascii
    $s4 = "var RmceW = new Date();" fullword ascii
    $s5 = "DsPVwCH + caJYm + bLvcCdRqCbYSSPx + XiReW + btOfskUZ + EpwLwiXYsMiEWwD + IbTmzowabUpq + lzckKNULhlUiYD, false);" fullword ascii
    $s6 = "function InkYUvEO(n)" fullword ascii
    $s7 = "function gyqbbDNTcg(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}