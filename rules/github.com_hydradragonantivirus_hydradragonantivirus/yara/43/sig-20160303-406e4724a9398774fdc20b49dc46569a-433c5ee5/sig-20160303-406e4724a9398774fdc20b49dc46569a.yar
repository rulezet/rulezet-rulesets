rule sig_20160303_406e4724a9398774fdc20b49dc46569a {
  meta:
    description = "datamaliciousorder - file 20160303_406e4724a9398774fdc20b49dc46569a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f9b464f36f868120ab44143d4fd3f243f93e23914a73d85af6d4b38ca91b28e"

  strings:
    $s1  = "var cl = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(VQnuH);" fullword ascii
    $s3  = "var WZs = (fTi + \"TTP\" + \" crbfGzc mPPXh XML ream St NorMmOha AD lNmwBQd OD\").split(\" \");" fullword ascii
    $s4  = "var xV = true  , AXcv = WZs[7] + \"\" + WZs[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + jRDiDLb + \".F\" + UVEkkeltVW + OwReE + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "BrRYX.open(zfefn,zIBvi,false);" fullword ascii
    $s7  = "if (((new Date())>0,7320808888)) {" fullword ascii
    $s8  = "function uJFu(aSOwp,vbSnd) {" fullword ascii
    $s9  = "function KaIEvYrq() {" fullword ascii
    $s10 = "function nIXB(hPwZK) {" fullword ascii
    $s11 = "function jaJRw(XwMEPb) {" fullword ascii
    $s12 = "function jCbZnKf(IlGs) {" fullword ascii
    $s13 = "function VNpZ(VQnuH) {" fullword ascii
    $s14 = "function NuaJ(rcwDq) {" fullword ascii
    $s15 = "dtv = p; break; " fullword ascii
    $s16 = "function ZFUTXyKNB(ziLVt,wSSGy,qWFuE) {" fullword ascii
    $s17 = "return Wwlio.status;" fullword ascii
    $s18 = "function xDEM(nrRDd) {" fullword ascii
    $s19 = "function Cfjl(xQCID,XkMym) {" fullword ascii
    $s20 = "return new ActiveXObject(XwMEPb);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}