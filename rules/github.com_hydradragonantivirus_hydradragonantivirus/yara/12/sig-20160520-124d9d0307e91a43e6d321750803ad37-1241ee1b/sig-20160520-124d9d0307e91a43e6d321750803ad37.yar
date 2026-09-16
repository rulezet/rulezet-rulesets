rule sig_20160520_124d9d0307e91a43e6d321750803ad37 {
  meta:
    description = "datamaliciousorder - file 20160520_124d9d0307e91a43e6d321750803ad37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf279541e40bbbecaf63b7ff0bbd54566474254f1a7b012224fe089fbcfa5795"

  strings:
    $s1  = "function HhfCjpKG(AugOE) {var bfqTpRes=KyNTl[2];for(var PcxzF=0;PcxzF<AugOE;PcxzF++){Xmmrp+=bfqTpRes.charAt(Math.floor(Math.rand" ascii
    $s2  = "function HhfCjpKG(AugOE) {var bfqTpRes=KyNTl[2];for(var PcxzF=0;PcxzF<AugOE;PcxzF++){Xmmrp+=bfqTpRes.charAt(Math.floor(Math.rand" ascii
    $s3  = "function VqfGv(ngyrwNdz,OHilOQ,XtvWiqhba){JbQdh=ngyrwNdz.split(XtvWiqhba);QUIFBWz = KyNTl[13];for(TVMltlhZ=0;TVMltlhZ<OHilOQ.len" ascii
    $s4  = "function GoKw(gCDujU,qQoxgBs){PMUV = KyNTl[11].split(KyNTl[12]);qQoxgBs.open(PMUV[0]+PMUV[2]+PMUV[3], gCDujU, false);qQoxgBs.sen" ascii
    $s5  = "function TtDfszU() {var EIAO=100000;var bIuRgI = 100;return Math.random()*(EIAO-bIuRgI)+bIuRgI;}" fullword ascii
    $s6  = "function CuPawZ(koUhBI){return koUhBI.ExpandEnvironmentStrings(KyNTl[10])}" fullword ascii
    $s7  = "try{sMKgnwv=YZuFfvwAc(GTJLs[vXDV], TtDfszU() + KyNTl[9], 1)}catch(e){}; " fullword ascii
    $s8  = "if (sMKgnwv==0) break;" fullword ascii
    $s9  = "gth;TVMltlhZ++) {QUIFBWz+=JbQdh[OHilOQ[TVMltlhZ]];}return QUIFBWz.substring(3,QUIFBWz.length);}" fullword ascii
    $s10 = "function MQoNT(koUhBI){return new ActiveXObject(koUhBI);}" fullword ascii
    $s11 = "function GoKw(gCDujU,qQoxgBs){PMUV = KyNTl[11].split(KyNTl[12]);qQoxgBs.open(PMUV[0]+PMUV[2]+PMUV[3], gCDujU, false);qQoxgBs.sen" ascii
    $s12 = "function wsiLg(Ciefjzar,STRpH,AuVjgbKBXF){Ciefjzar.open();Ciefjzar.type = 1;Ciefjzar.write(STRpH);Ciefjzar.position = 0;Ciefjzar" ascii
    $s13 = "function wsiLg(Ciefjzar,STRpH,AuVjgbKBXF){Ciefjzar.open();Ciefjzar.type = 1;Ciefjzar.write(STRpH);Ciefjzar.position = 0;Ciefjzar" ascii
    $s14 = "om()*bfqTpRes.length));}return Xmmrp;}" fullword ascii
    $s15 = "function YZuFfvwAc(keetFrROj,Xlrputp,OITsXkQN){" fullword ascii
    $s16 = "function VqfGv(ngyrwNdz,OHilOQ,XtvWiqhba){JbQdh=ngyrwNdz.split(XtvWiqhba);QUIFBWz = KyNTl[13];for(TVMltlhZ=0;TVMltlhZ<OHilOQ.len" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}