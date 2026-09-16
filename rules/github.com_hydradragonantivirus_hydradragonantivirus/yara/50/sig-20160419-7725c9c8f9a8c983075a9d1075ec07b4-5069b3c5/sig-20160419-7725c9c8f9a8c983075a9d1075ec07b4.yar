rule sig_20160419_7725c9c8f9a8c983075a9d1075ec07b4 {
  meta:
    description = "datamaliciousorder - file 20160419_7725c9c8f9a8c983075a9d1075ec07b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "491eac3bd1238cf13b36c5fc09f7a5e3923b193ec58118b8fe07ab309948452d"

  strings:
    $s1  = "return inzkuds[0] + inzkuds[2] + inzkuds[4] + \".F\" + inzkuds[7] + inzkuds[9] + inzkuds[12] + inzkuds[14];" fullword ascii
    $s2  = "var rd = true  , Vgqn = Ykm[7] + Ykm[9] + Ykm[11];" fullword ascii
    $s3  = "function EgJXzX(Icmd,NPiLsg) {" fullword ascii
    $s4  = "bmlV.open(SVwOz,etdEj,false);" fullword ascii
    $s5  = "var Ykm = (\"2.XMLHTTP NftZmED iqUYc XML ream St dyLwWUTd AD pKkfjct O SfCo D\").split(\" \");" fullword ascii
    $s6  = "if (N >= CiMiO.length) {break;}" fullword ascii
    $s7  = "function FVZzm(fXoUsq) {" fullword ascii
    $s8  = "function daylc(EWvMVX) {" fullword ascii
    $s9  = "return mlAN[vsoulHp[0]+vsoulHp[1]];" fullword ascii
    $s10 = "function UYkT(WQZxa,etdEj,SVwOz) {" fullword ascii
    $s11 = "if (BKsIi != 538-338){return false;} else {return true;}" fullword ascii
    $s12 = "function cnOe(QnSDJ) {" fullword ascii
    $s13 = "return LCiIIms;" fullword ascii
    $s14 = "return KTZTW;" fullword ascii
    $s15 = "return EWvMVX[sJrE[115-115]]=265-265;" fullword ascii
    $s16 = "function KFSbdYR(mlAN) {" fullword ascii
    $s17 = "function llhDjMkB(dvC) {" fullword ascii
    $s18 = "return bXvUGWi[0];" fullword ascii
    $s19 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s20 = "function jRrs(BKsIi) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}