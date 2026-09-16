rule sig_20160323_4c85de23d7f06ab8c182c52af3764f26 {
  meta:
    description = "datamaliciousorder - file 20160323_4c85de23d7f06ab8c182c52af3764f26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72502bad9b489310bb5e1769d697572d06910a546e05144ef3a7e9db8bfa4932"

  strings:
    $s1  = "return WScript.CreateObject(XgRJw);" fullword ascii
    $s2  = "return TivrVDV[0] + TivrVDV[2] + TivrVDV[4] + \".F\" + TivrVDV[7] + TivrVDV[9] + TivrVDV[12] + TivrVDV[14];" fullword ascii
    $s3  = "var vp = true  , yVgb = oCx[7] + oCx[9] + oCx[11];" fullword ascii
    $s4  = "var oCx = (\"2.XMLHTTP vWYeJIW zVuju XML ream St gYbdLPbT AD TyzwKMn O SlyH D\").split(\" \");" fullword ascii
    $s5  = "var TivrVDV = supdp(dkfHqKdCwE+\" \"+\"System PJ PbDht Obj JRoFmp ect lDtoycz dmJFl\", \" \");" fullword ascii
    $s6  = "frGd.open(Gqzdf,bkDyx,false);" fullword ascii
    $s7  = "function QFVsiLrx(spc) {" fullword ascii
    $s8  = "return new ActiveXObject(auYw);" fullword ascii
    $s9  = "function WwRim(vDNBTm) {" fullword ascii
    $s10 = "return oIvKHG/*wOXNt5NwLAxQBrFN3aV6IDvte*/.position=108-108;" fullword ascii
    $s11 = "function qcPm(UjCnr,bkDyx,Gqzdf) {" fullword ascii
    $s12 = "return spc.size;" fullword ascii
    $s13 = "function HYmFR(oIvKHG) {" fullword ascii
    $s14 = "function XnPR(kHByP,OSuSM) {" fullword ascii
    $s15 = "function CkAwzVTS(tWeI) {" fullword ascii
    $s16 = "function ZzcI(VyHzD) {" fullword ascii
    $s17 = "XkL = n; break; " fullword ascii
    $s18 = "function NmZWUZh(JvNg,lyaeL) {" fullword ascii
    $s19 = "return VyHzD.status;" fullword ascii
    $s20 = "function vGsMuhNHu(YlqysecxKjB) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}