rule sig_20160404_79f95119ffaa8b75328b2d3362c677b6 {
  meta:
    description = "datamaliciousorder - file 20160404_79f95119ffaa8b75328b2d3362c677b6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4027e9b9baff317de57170cb3483e403919931062b1e76e076747145bccad70b"

  strings:
    $s1  = "var tG = true  , RQMK = MtL[7] + MtL[9] + MtL[11];" fullword ascii
    $s2  = "return ROPPgps[0] + ROPPgps[2] + ROPPgps[4] + \".F\" + ROPPgps[7] + ROPPgps[9] + ROPPgps[12] + ROPPgps[14];" fullword ascii
    $s3  = "var ROPPgps = pwMWS(HyDsPryihM+\" \"+\"System DL CZhck Obj XdaNXP ect kaHVZhL MFAeD\", \" \");" fullword ascii
    $s4  = "qqkQ.open(bNFoJ,dHtNH,false);" fullword ascii
    $s5  = "var MtL = (\"2.XMLHTTP VgmChit ifvEQ XML ream St pwwlSILB AD hLPzmja O eqCE D\").split(\" \");" fullword ascii
    $s6  = "function xmTiO(NuXFQE) {" fullword ascii
    $s7  = "function XgJE(bufeQ) {" fullword ascii
    $s8  = "return zXk.split(cNhtX);" fullword ascii
    $s9  = "function BangGm(tJCI,sQqjIl) {" fullword ascii
    $s10 = "function tXdBbnEsX(ROJuA) {" fullword ascii
    $s11 = "if (DxGgD > 159282-146){return true;} else {return false;}" fullword ascii
    $s12 = "function MOcJ(nVKer) {" fullword ascii
    $s13 = "function VKOSiBk(qRFg) {" fullword ascii
    $s14 = "Xsf = t; break; " fullword ascii
    $s15 = "return wKLwGcJ(qL,IcqOp[810-804]+IcqOp[376-369]+IcqOp[664-656]);" fullword ascii
    $s16 = "function wKLwGcJ(KbIr,mDuXX) {" fullword ascii
    $s17 = "if(t>=y.length) {break;}" fullword ascii
    $s18 = "function BEwoM(vxWmao) {" fullword ascii
    $s19 = "function SFkdD(ZZDyxbos,EjjC) {" fullword ascii
    $s20 = "if (j >= nVKer.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}