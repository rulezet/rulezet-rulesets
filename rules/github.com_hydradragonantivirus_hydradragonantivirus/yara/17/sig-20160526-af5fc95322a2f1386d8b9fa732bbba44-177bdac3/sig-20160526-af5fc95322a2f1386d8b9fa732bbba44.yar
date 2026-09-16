rule sig_20160526_af5fc95322a2f1386d8b9fa732bbba44 {
  meta:
    description = "datamaliciousorder - file 20160526_af5fc95322a2f1386d8b9fa732bbba44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a95b195421f0f3925caf479d9585ffb68e028fbba934bc0eadbeb37785b215e3"

  strings:
    $s1  = "th.sin(407), 2) + Math.pow(Math.cos(407), 2) - 1))-867)) onGTrsTfrg += VJbDNZZmMoBI(pCSHHU, TQipDUXsuYcOsqOqRAzqVDE);else onGTrs" ascii
    $s2  = "function WHVLKhZHgQG(pOIRyLGeNkzCw) {var LRRAvn = crvipega.join(siKTb[0]);var pCSHHU, TQipDUXsuYcOsqOqRAzqVDE, sRGNuwIjvengaYM, " ascii
    $s3  = " Math.pow(Math.cos(841), 2) - 1))-324) | NPbkYpboaOUEGTNEIpdFpib<< (486 + Math.round((Math.pow(Math.sin(627), 2) + Math.pow(Math" ascii
    $s4  = "6), 2) + Math.pow(Math.cos(876), 2) - 1))-17)) onGTrsTfrg += cH(pCSHHU);else if (WMolBUFHGSATp == (931 + Math.round((Math.pow(Ma" ascii
    $s5  = "function ClphrFfnmCBifZusJwBoZt(UYqlpjSwkgvwuUSiKrTHg,IPGVX){return UYqlpjSwkgvwuUSiKrTHg.charAt(IPGVX);}" fullword ascii
    $s6  = "function VJbDNZZmMoBI(nOVFiGO,znKgcUqYthgNkWpgeS){return String.fromCharCode(nOVFiGO,znKgcUqYthgNkWpgeS);}" fullword ascii
    $s7  = "function AKlBoYy(VMJXbcU,RplylpcHXMsCgahKH,LHBnXigomgp){return String.fromCharCode(VMJXbcU,RplylpcHXMsCgahKH,LHBnXigomgp);}" fullword ascii
    $s8  = "function WHVLKhZHgQG(pOIRyLGeNkzCw) {var LRRAvn = crvipega.join(siKTb[0]);var pCSHHU, TQipDUXsuYcOsqOqRAzqVDE, sRGNuwIjvengaYM, " ascii
    $s9  = "function cH(HHiDN){return String.fromCharCode(HHiDN);}" fullword ascii
    $s10 = "Tfrg += AKlBoYy(pCSHHU, TQipDUXsuYcOsqOqRAzqVDE, sRGNuwIjvengaYM);} while (vwbNGBrBmnVdy < pOIRyLGeNkzCw.length);return onGTrsTf" ascii
    $s11 = "function XfNTbqcoPgNMtPHc(cfyAabpPMgMPXvMT,XjKxTiuqkkEjTqHais){return cfyAabpPMgMPXvMT.indexOf(XjKxTiuqkkEjTqHais);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}