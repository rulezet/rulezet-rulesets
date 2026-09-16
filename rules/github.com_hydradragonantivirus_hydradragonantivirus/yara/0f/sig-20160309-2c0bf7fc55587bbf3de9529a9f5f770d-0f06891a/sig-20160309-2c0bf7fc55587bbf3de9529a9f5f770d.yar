rule sig_20160309_2c0bf7fc55587bbf3de9529a9f5f770d {
  meta:
    description = "datamaliciousorder - file 20160309_2c0bf7fc55587bbf3de9529a9f5f770d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "072c45b078eaa3431670da4b843660a5da86598019f458bdfbac8ad24bcb893d"

  strings:
    $s1  = "return JhkmydZ[0] + JhkmydZ[2] + JhkmydZ[4] + \".F\" + JhkmydZ[7] + JhkmydZ[9] + JhkmydZ[12] + JhkmydZ[14];" fullword ascii
    $s2  = "var Nv = true  , IMyu = vpm[7] + vpm[9] + vpm[11];" fullword ascii
    $s3  = "var JhkmydZ = \"Sc BTXSQmG r fxiiqsuks ipting FRZfrIm yyn ile oiNpgLRNyHRfpu System tw AnwWI Obj wbsPDO ect RddSKoF\".split(\" " ascii
    $s4  = "var vpm = (\"2.XMLHTTP MZZMPIv dcXnh XML ream St fzCnvKqf AD eTtVZCd O RtnC D\").split(\" \");" fullword ascii
    $s5  = "GLUzz.open(wUHyb,nUfHr,false);" fullword ascii
    $s6  = "function LOuvryBV() {" fullword ascii
    $s7  = "function MekZ(oPAbu) {" fullword ascii
    $s8  = "return Gbl.size;" fullword ascii
    $s9  = "function Vdgr(oRfwW) {" fullword ascii
    $s10 = "function CXsu(NOcMm) {" fullword ascii
    $s11 = "function GruCPcs(BGox,tbSGx) {" fullword ascii
    $s12 = "function qjCz(bwCHm) {" fullword ascii
    $s13 = "function InnC(mDBLt,WQETo) {" fullword ascii
    $s14 = "if (hzySL > 188251-590){return true;} else {return false;}" fullword ascii
    $s15 = "function JLEMsOUuM(yRJLn,obFgc,YdRUF,oNHh) {" fullword ascii
    $s16 = "function mCLnOiH(BQGT) {" fullword ascii
    $s17 = "function Hjke(GLUzz,nUfHr,wUHyb) {" fullword ascii
    $s18 = "return bwCHm.status;" fullword ascii
    $s19 = "function lbzzHwDBQ(khZzjVEJnMO) {" fullword ascii
    $s20 = "return new ActiveXObject(LwspAG);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}