rule sig_20160301_d831719f331502f76ee7e64fdf9fa31a {
  meta:
    description = "datamaliciousorder - file 20160301_d831719f331502f76ee7e64fdf9fa31a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd774f3d1bc7a71b726fdd08c95608dbe94e02a05cd17f7cc03b1402e3ef0441"

  strings:
    $s1  = "var kk = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(sWDXd);" fullword ascii
    $s3  = "var thr = (VNg + \"TTP\" + \" zYmXQrQ MIFEe XML ream St tkYumYEL AD MQhmXGl OD\").split(\" \");" fullword ascii
    $s4  = "var mp = true  , RkFX = thr[7] + \"\" + thr[9];" fullword ascii
    $s5  = "return \"Sc\" + \"r\" + DWpTroe + \".F\" + vFAbwZrUru + aioaO + \"Obj\" + \"ect\";" fullword ascii
    $s6  = "eGeBa.open(XEEig,aBgnC,false);" fullword ascii
    $s7  = "function mWuK(tMpdL) {" fullword ascii
    $s8  = "return QjNqr.status;" fullword ascii
    $s9  = "sSS = D; break; " fullword ascii
    $s10 = "function eULJHngm() {" fullword ascii
    $s11 = "function Cyal(xAxIl,BLook) {" fullword ascii
    $s12 = "function QMKGOTend(OBxne,hlEgK,uyZfr) {" fullword ascii
    $s13 = "if (pKmWT == 1082-882){return true;} else {return false;}" fullword ascii
    $s14 = "if (((new Date())>0,7264685888)) {" fullword ascii
    $s15 = "function ZMym(HlZYD,sWLCZ) {" fullword ascii
    $s16 = "return rI.ExpandEnvironmentStrings(kk);" fullword ascii
    $s17 = "function OQQc(fQpIz) {" fullword ascii
    $s18 = "return new ActiveXObject(uhOPJU);" fullword ascii
    $s19 = "function duCBz(uhOPJU) {" fullword ascii
    $s20 = "function iGiJ(tKLJh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}