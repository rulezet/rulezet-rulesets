rule sig_20160419_ba05689d030da1401f16e975d78d69c6 {
  meta:
    description = "datamaliciousorder - file 20160419_ba05689d030da1401f16e975d78d69c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a985adf662fedbca7bb36e90b64d12010e375d7e1fb28c808d313330dc8527ff"

  strings:
    $s1  = "return SjQBzOy[0] + SjQBzOy[2] + SjQBzOy[4] + \".F\" + SjQBzOy[7] + SjQBzOy[9] + SjQBzOy[12] + SjQBzOy[14];" fullword ascii
    $s2  = "var dy = true  , NyAG = xCC[7] + xCC[9] + xCC[11];" fullword ascii
    $s3  = "var xCC = (\"2.XMLHTTP IEuHbxg Rpjir XML ream St WllAHBLL AD aLZORtj O mPVb D\").split(\" \");" fullword ascii
    $s4  = "lYXo.open(nNTFM,tzVEn,false);" fullword ascii
    $s5  = "if(H>=C.length) {break;}" fullword ascii
    $s6  = "function ceQN(TgQUg) {" fullword ascii
    $s7  = "if (j >= Muoqk.length) {break;}" fullword ascii
    $s8  = "function ltuaz(qRF,LgmaO) {" fullword ascii
    $s9  = "function srGJCQDt(mSC) {" fullword ascii
    $s10 = "function cNGRR(nfJXLg) {" fullword ascii
    $s11 = "return JflzOVj;" fullword ascii
    $s12 = "function lIIx(YEfcn) {" fullword ascii
    $s13 = "function teeZbwGHg(KiOQX) {" fullword ascii
    $s14 = "function eaUt(dspGd,ndZrj) {" fullword ascii
    $s15 = "function nOpj(Muoqk) {" fullword ascii
    $s16 = "function xDSaaG(prKF,tENtjk) {" fullword ascii
    $s17 = "function lJaE(HeEkH) {" fullword ascii
    $s18 = "return DlsOhnB[0];" fullword ascii
    $s19 = "return qRF[qsnL[0]](LgmaO);" fullword ascii
    $s20 = "return zlPPE;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}