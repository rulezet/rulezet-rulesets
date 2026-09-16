rule sig_20160312_3540449297d017e8f71c847137428768 {
  meta:
    description = "datamaliciousorder - file 20160312_3540449297d017e8f71c847137428768.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba6a72fbfafc12fd666f5556bf3d2fd6ff9e754a23fab4d1efd449b0897f9383"

  strings:
    $s1  = "var mC = true  , eOuN = okz[7] + okz[9] + okz[11];" fullword ascii
    $s2  = "return pJxJZOX[0] + pJxJZOX[2] + pJxJZOX[4] + \".F\" + pJxJZOX[7] + pJxJZOX[9] + pJxJZOX[12] + pJxJZOX[14];" fullword ascii
    $s3  = "var pJxJZOX = \"Sc vuDGmgH r PVrOIBpYv ipting PGDPtWz oNP ile zPTzVlfJRxNCYs System Qi rradd Obj MPEdiJ ect XpBhLrY\".split(\" " ascii
    $s4  = "ighYF.open(wVwQL,EYGvR,false);" fullword ascii
    $s5  = "return qWbUr.status;" fullword ascii
    $s6  = "function SEdo(qWbUr) {" fullword ascii
    $s7  = "function nHHF(skQDV) {" fullword ascii
    $s8  = "function HbbC(dQDHV) {" fullword ascii
    $s9  = "function BlGO(otnug,IOYgk) {" fullword ascii
    $s10 = "if(K>=u.length) {break;}" fullword ascii
    $s11 = "return gJE.size;" fullword ascii
    $s12 = "return new ActiveXObject(HlVwbe);" fullword ascii
    $s13 = "return OsxTsLF(gR,rNVIL[869-863]+rNVIL[966-959]+rNVIL[400-392]);" fullword ascii
    $s14 = "function yqjE(ighYF,EYGvR,wVwQL) {" fullword ascii
    $s15 = "return iBHa.responseBody;" fullword ascii
    $s16 = "function glrA(RytLM) {" fullword ascii
    $s17 = "return hVmDtkx" fullword ascii
    $s18 = "return zkhW.ExpandEnvironmentStrings(RDPbE);" fullword ascii
    $s19 = "function bnXM(slSON) {" fullword ascii
    $s20 = "return tAZxl;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}