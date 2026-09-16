rule sig_20160314_ca4829ccf13449810f5398c99fca0370 {
  meta:
    description = "datamaliciousorder - file 20160314_ca4829ccf13449810f5398c99fca0370.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f1b477d6581945792b4447ad8a22aae0270ab5c8c7f4ff2f4f05b345bb0a6a2"

  strings:
    $s1 = "return joVSrR + oiAKCEFdTOe + RTBTTkmNXsZfE + NyQFVmb + rXGUDqmA + NaMiDXpzghYPDl + zzJTRO + DFcRzqpkrAT" fullword ascii
    $s2 = "maaXLTrjUpLz.open(BiQXiOSyMC, fLaPaRk + UQZruUGpzIa + WlpwtUyrxzSh + eIXpUKhHM + kruPt + USlWWouUXQ + OMYiigzZkYpkC + EcyjHujErH" ascii
    $s3 = "while (maaXLTrjUpLz.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s4 = "U + oMfVpfzGkGCWcr + gbSkveSu + WxHRfFJ + xPvHh + BzIOROMdMIYLL + bPcTulyIzaV + AWgSzKbaiPbQoud, false);" fullword ascii
    $s5 = "function HLvUogQWkWCgfOY(n)" fullword ascii
    $s6 = "var StxSWlipljV = new Date();" fullword ascii
    $s7 = "function jzBRpGoQ(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}