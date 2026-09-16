rule sig_20160520_3299516aa58ffa280934d3571af813d1 {
  meta:
    description = "datamaliciousorder - file 20160520_3299516aa58ffa280934d3571af813d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89e963aebea27076c7c462569904b79146e01ec34cb78528b7dabe37af2ed879"

  strings:
    $s1  = "function UbDCXjfF(BGWQc) {var wobAlSCt=vNpGwtnBXMwiwmc[2];for(var eTnFF=0;eTnFF<BGWQc;eTnFF++){dzJUH+=wobAlSCt.charAt(Math.floor" ascii
    $s2  = "function UbDCXjfF(BGWQc) {var wobAlSCt=vNpGwtnBXMwiwmc[2];for(var eTnFF=0;eTnFF<BGWQc;eTnFF++){dzJUH+=wobAlSCt.charAt(Math.floor" ascii
    $s3  = "function fBonQ(lLfBJXEK,bkDrS,jtSmfTmPLu){lLfBJXEK.open();lLfBJXEK.type = 1;lLfBJXEK.write(bkDrS);lLfBJXEK.position = 0;lLfBJXEK" ascii
    $s4  = "function fBonQ(lLfBJXEK,bkDrS,jtSmfTmPLu){lLfBJXEK.open();lLfBJXEK.type = 1;lLfBJXEK.write(bkDrS);lLfBJXEK.position = 0;lLfBJXEK" ascii
    $s5  = "JpSvPk.length;ICpSVSOO++) {CLiSuUC+=bSuZV[JpSvPk[ICpSVSOO]];}return CLiSuUC.substring(3,CLiSuUC.length);}" fullword ascii
    $s6  = ", false);lZwaJbl.send();}" fullword ascii
    $s7  = "function YFkN(bnpsST,lZwaJbl){OVpk = vNpGwtnBXMwiwmc[11].split(vNpGwtnBXMwiwmc[12]);lZwaJbl.open(OVpk[0]+OVpk[2]+OVpk[3], bnpsST" ascii
    $s8  = "if (pWMAgUc==0) break;" fullword ascii
    $s9  = "try{pWMAgUc=uMEsniJva(qaIqJ[BHWf], VNWBuBT() + vNpGwtnBXMwiwmc[9], 1)}catch(e){}; " fullword ascii
    $s10 = "function FYMOcI(eIskrq){return eIskrq.ExpandEnvironmentStrings(vNpGwtnBXMwiwmc[10])}" fullword ascii
    $s11 = "function uMEsniJva(efJCEkTZt,TDCngtY,GvsyoJhO){" fullword ascii
    $s12 = "function nkKpR(FUAvWdYq,JpSvPk,WaMSuZASX){bSuZV=FUAvWdYq.split(WaMSuZASX);CLiSuUC = vNpGwtnBXMwiwmc[13];for(ICpSVSOO=0;ICpSVSOO<" ascii
    $s13 = "function VNWBuBT() {var dpUL=100000;var bZtEGp = 100;return Math.random()*(dpUL-bZtEGp)+bZtEGp;}" fullword ascii
    $s14 = "function nkKpR(FUAvWdYq,JpSvPk,WaMSuZASX){bSuZV=FUAvWdYq.split(WaMSuZASX);CLiSuUC = vNpGwtnBXMwiwmc[13];for(ICpSVSOO=0;ICpSVSOO<" ascii
    $s15 = "function EAMfB(eIskrq){return new ActiveXObject(eIskrq);}" fullword ascii
    $s16 = "function YFkN(bnpsST,lZwaJbl){OVpk = vNpGwtnBXMwiwmc[11].split(vNpGwtnBXMwiwmc[12]);lZwaJbl.open(OVpk[0]+OVpk[2]+OVpk[3], bnpsST" ascii
    $s17 = "(Math.random()*wobAlSCt.length));}return dzJUH;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}