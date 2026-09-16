rule sig_20160323_ee945cb92e15e28f366d718be27a206b {
  meta:
    description = "datamaliciousorder - file 20160323_ee945cb92e15e28f366d718be27a206b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79fb71915ab02b928096d8da2503be5529b43a331ec69ea462cc7762c65639d3"

  strings:
    $s1  = "return WScript.CreateObject(ULrvv);" fullword ascii
    $s2  = "return hPCUvQm[0] + hPCUvQm[2] + hPCUvQm[4] + \".F\" + hPCUvQm[7] + hPCUvQm[9] + hPCUvQm[12] + hPCUvQm[14];" fullword ascii
    $s3  = "var UK = true  , QwCq = Rjy[7] + Rjy[9] + Rjy[11];" fullword ascii
    $s4  = "function TmpYQiND(mxs) {" fullword ascii
    $s5  = "iNxP.open(EAkON,LbTzf,false);" fullword ascii
    $s6  = "var hPCUvQm = kuoIL(QJjsAHrDyj+\" \"+\"System ig DyWhC Obj PAnlBi ect Kagzfhm pEnmQ\", \" \");" fullword ascii
    $s7  = "var Rjy = (\"2.XMLHTTP oKPTJgM aoCmh XML ream St yJKElQDL AD ASjmbSb O DYyb D\").split(\" \");" fullword ascii
    $s8  = "if(l>=J.length) {break;}" fullword ascii
    $s9  = "function bvWiT(BVjfwd) {" fullword ascii
    $s10 = "function cUMs(syCCF,jTbIH) {" fullword ascii
    $s11 = "return JOT.split(PyyiC);" fullword ascii
    $s12 = "function xcTZ(VTqQi) {" fullword ascii
    $s13 = "return mxs.size;" fullword ascii
    $s14 = "return BVjfwd/*xyPujP55G4GHyjAfO7hcXOnwv*/.position=884-884;" fullword ascii
    $s15 = "function zotDlRfUi(xTOeMLPEqQQ) {" fullword ascii
    $s16 = "function GoNfO(hOnEwG) {" fullword ascii
    $s17 = "function hPwe(iZcxz) {" fullword ascii
    $s18 = "function EwBN(RzIZp,FnZPG) {" fullword ascii
    $s19 = "function CvBXzSS(Oiqg,WyrsH) {" fullword ascii
    $s20 = "if (VTqQi > 177779-736){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}