rule sig_20160310_745882c200d9b0cd6538126f15919a58 {
  meta:
    description = "datamaliciousorder - file 20160310_745882c200d9b0cd6538126f15919a58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289f6e8b51affc963594ba1ebac29f3d38dc8da797ead465da3ef58b09ab3464"

  strings:
    $s1  = "var TT = true  , UCIP = eOY[7] + eOY[9] + eOY[11];" fullword ascii
    $s2  = "return wQwHRqG[0] + wQwHRqG[2] + wQwHRqG[4] + \".F\" + wQwHRqG[7] + wQwHRqG[9] + wQwHRqG[12] + wQwHRqG[14];" fullword ascii
    $s3  = "var eOY = (\"2.XMLHTTP GDwpamf rxtXn XML ream St qutGGSEn AD HRUsYQU O CmIL D\").split(\" \");" fullword ascii
    $s4  = "skDsW.open(RcUrg,QCiyf,false);" fullword ascii
    $s5  = "var wQwHRqG = \"Sc lofSNrg r sZzobVLRE ipting yEPNGrn eXX ile HDdzUVPbxhCmQz System QK TgeHE Obj MeEiEc ect KySxOOe\".split(\" " ascii
    $s6  = "function Wtxw(PGARX) {" fullword ascii
    $s7  = "if(a>=W.length) {break;}" fullword ascii
    $s8  = "function haln(skDsW,QCiyf,RcUrg) {" fullword ascii
    $s9  = "function iqwB(WOWBa) {" fullword ascii
    $s10 = "return hjEiHKA(wl,WZHAs[698-692]+WZHAs[614-607]+WZHAs[622-614]);" fullword ascii
    $s11 = "if (ioobK > 197502-833){return true;} else {return false;}" fullword ascii
    $s12 = "function xNRm(MRVxD,MiVmf) {" fullword ascii
    $s13 = "return ZKu.size;" fullword ascii
    $s14 = "function PWAB(RuUrv) {" fullword ascii
    $s15 = "if (x >= RuUrv.length) {break;}" fullword ascii
    $s16 = "function qpncnDe(JDgn) {" fullword ascii
    $s17 = "function KhII(ioobK) {" fullword ascii
    $s18 = "function zfeCP(Wdjiah) {" fullword ascii
    $s19 = "return dWSI.ExpandEnvironmentStrings(DigEG);" fullword ascii
    $s20 = "function eFSos(gpqaih) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}