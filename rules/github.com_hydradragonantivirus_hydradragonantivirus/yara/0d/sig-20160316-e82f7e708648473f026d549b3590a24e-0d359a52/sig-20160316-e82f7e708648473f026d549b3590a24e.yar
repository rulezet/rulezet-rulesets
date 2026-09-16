rule sig_20160316_e82f7e708648473f026d549b3590a24e {
  meta:
    description = "datamaliciousorder - file 20160316_e82f7e708648473f026d549b3590a24e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c991c2ec18652b977a0be7499541ba106cdd3ce07b2612a81bb11841463ca3b"

  strings:
    $s1 = "while (mKhyJLKUeyqxuSf[tocEYttnRmhr + zzOzT + eFTWA + wmmrJGDtDDK + iKCfMRr + OSJQMnsG] < 4 ) {WScript[vfWARpbyDAL + ZWJCaUdSDtO" ascii
    $s2 = "while (mKhyJLKUeyqxuSf[tocEYttnRmhr + zzOzT + eFTWA + wmmrJGDtDDK + iKCfMRr + OSJQMnsG] < 4 ) {WScript[vfWARpbyDAL + ZWJCaUdSDtO" ascii
    $s3 = "+ aaadaxZ + fNPmrUeaIGiwhk + YLqmOTwTlsZ + RHZUPvEzQHhIFT + hBhwfbzUfW, false);" fullword ascii
    $s4 = "mKhyJLKUeyqxuSf[qEiT + ifagvzIlvQGlU](LMXZG, KlWKFxsLrIVFn + UMLxMDKJ + pBsR + feHxZthRL + IkSmgoWbKtRL + GyoXvRhe + BUrbpJfYzD " ascii
    $s5 = "function fxYdNbfsfoU(n){return CKKOKixVOabcK + sUVXJgD + xcjFQRS + MwnU + KBmCFf + lweGrrxGO + upOUJkOrxvY;}" fullword ascii
    $s6 = "var Iim = new Date();" fullword ascii
    $s7 = "function CRhvaxCgXYz(WORntYepcxoS){BmHy[QRvLhXjewgraSOB](WORntYepcxoS, 0, 0);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}