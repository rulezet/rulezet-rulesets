rule sig_20160411_35c0c38e09345684c5f3eb9e00b991db {
  meta:
    description = "datamaliciousorder - file 20160411_35c0c38e09345684c5f3eb9e00b991db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f885d45224684a0e9eaa2efedd87fd3bc4b02e733baf867668600616a6f31971"

  strings:
    $s1  = "var Rv = true  , xRWU = pQi[7] + pQi[9] + pQi[11];" fullword ascii
    $s2  = "return zkLIKIm[0] + zkLIKIm[2] + zkLIKIm[4] + \".F\" + zkLIKIm[7] + zkLIKIm[9] + zkLIKIm[12] + zkLIKIm[14];" fullword ascii
    $s3  = "Wqnl.open(fjMLs,VdwAo,false);" fullword ascii
    $s4  = "if (autHA == 342-142){return true;} else {return false;}" fullword ascii
    $s5  = "var pQi = (\"2.XMLHTTP SRGiiJT POrhM XML ream St srgtaiqi AD OJwhyoz O twfg D\").split(\" \");" fullword ascii
    $s6  = "function DKvi(autHA) {" fullword ascii
    $s7  = "if(e>=f.length) {break;}" fullword ascii
    $s8  = "return gEjyNVy(kJ,TrzGnU+IFiWJ[304-296]);" fullword ascii
    $s9  = "return HvKvd;" fullword ascii
    $s10 = "return zqJGE.status;" fullword ascii
    $s11 = "function UXTJgajoq(jgNIKfsLEHp) {" fullword ascii
    $s12 = "return EQxA[LJYuyoR[0]+LJYuyoR[1]];" fullword ascii
    $s13 = "function KNVjk(lXVDEjaC,YQSv) {" fullword ascii
    $s14 = "function wHCv(UpUrT) {" fullword ascii
    $s15 = "return apKnvww;" fullword ascii
    $s16 = "function MmpJV(bDamuv) {" fullword ascii
    $s17 = "if (AsgUV > 182993-460){return true;} else {return false;}" fullword ascii
    $s18 = "function kVrSrigDP(ooPNw) {" fullword ascii
    $s19 = "function yhijZj(PPAQ,ntCyYh) {" fullword ascii
    $s20 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}