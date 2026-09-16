rule sig_20160404_fbc053b281924107241d46d35aa05f06 {
  meta:
    description = "datamaliciousorder - file 20160404_fbc053b281924107241d46d35aa05f06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "240f172d022a259ce8cdb160b4f766f4b4778610d6df59b9736229a5adeb7ea5"

  strings:
    $s1  = "var nPR = npxI(arNI + \"B.\" + wlP[5]+(437567, wlP[4]));" fullword ascii
    $s2  = "var am = true  , arNI = wlP[7] + wlP[9] + wlP[11];" fullword ascii
    $s3  = "return OebEmZM[0] + OebEmZM[2] + OebEmZM[4] + \".F\" + OebEmZM[7] + OebEmZM[9] + OebEmZM[12] + OebEmZM[14];" fullword ascii
    $s4  = "var OebEmZM = usZon(OGhUFHzXtJ+\" \"+\"System gU oLfXs Obj RsrcHj ect FFYHtsi yMJWe\", \" \");" fullword ascii
    $s5  = "RbAV.open(oBRkI,ukfXK,false);" fullword ascii
    $s6  = "var wlP = (\"2.XMLHTTP stxnPnZ chCeg XML ream St LmcllvTk AD MXzLHtp O Cfhy D\").split(\" \");" fullword ascii
    $s7  = "function Ktbu(QZznM,aDxGP) {" fullword ascii
    $s8  = "function RajaML(pvJcNEN) {" fullword ascii
    $s9  = "function hDtU(KmiqH) {" fullword ascii
    $s10 = "return tIFhL;" fullword ascii
    $s11 = "if (NQFsk == 356-156){return true;} else {return false;}" fullword ascii
    $s12 = "return nAVjsQs(Bh,GripN[329-323]+GripN[345-338]+GripN[254-246]);" fullword ascii
    $s13 = "return new ActiveXObject(LtfY);" fullword ascii
    $s14 = "function FZUNT(xkaomZ) {" fullword ascii
    $s15 = "if(k>=C.length) {break;}" fullword ascii
    $s16 = "function nAVjsQs(cfcP,EuTJk) {" fullword ascii
    $s17 = "function usZon(cZl,eaxFk) {" fullword ascii
    $s18 = "function vafRzLzg(YUU) {" fullword ascii
    $s19 = "if (QglDL > 181289-488){return true;} else {return false;}" fullword ascii
    $s20 = "function Hlce(rjFwc,oOXdz) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}