rule sig_20160527_052ce69733aed537e2b35d26a291c5f2 {
  meta:
    description = "datamaliciousorder - file 20160527_052ce69733aed537e2b35d26a291c5f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "578fbb98b6bba6dd830eaf4e6376522925781bf4212499bdb4cb252f04e386de"

  strings:
    $s1  = "function BQIUO() {return WScript;}function XbMNRUv(){return rpclOmAKbjLJCK.ExpandEnvironmentStrings(zbvBjGXsvl())}" fullword ascii
    $s2  = "function ruXqmdHZfmOsVUvsWGKftvU(vNXYJOzbayzsvuWexEsxTHao,cFCph){return vNXYJOzbayzsvuWexEsxTHao.charAt(cFCph);}" fullword ascii
    $s3  = "var AEXoFNPKX=function(){return new ActiveXObject(JMlZxXLDn[0]);}();" fullword ascii
    $s4  = "function iUDfqnwJYvWOtOvzBGwQaIqT(sqlwRKpo,oLIbPrt){return String.fromCharCode(sqlwRKpo,oLIbPrt);}" fullword ascii
    $s5  = "var XAfSc = AEXoFNPKX.createtextfile(rpclOmAKbjLJCK.ExpandEnvironmentStrings(JMlZxXLDn[2]+JMlZxXLDn[3])+String.fromCharCode(92)+" ascii
    $s6  = "JMlZxXLDn[4],true);" fullword ascii
    $s7  = "(vkhqfDQXqX=0;vkhqfDQXqX<QmdOYKzJjfqmh.length;vkhqfDQXqX++) {ZpUXOiEy+=wKsXpOrW[QmdOYKzJjfqmh[vkhqfDQXqX]];}return ZpUXOiEy.subs" ascii
    $s8  = "function oO(xotGfXnR){return String.fromCharCode(xotGfXnR);}" fullword ascii
    $s9  = "function NcwnDqVRv(srFBbXePPBy,QmdOYKzJjfqmh,uNBWfbgAxwUp){wKsXpOrW=srFBbXePPBy.split(uNBWfbgAxwUp);ZpUXOiEy = JMlZxXLDn[14];for" ascii
    $s10 = "function zbvBjGXsvl(){return NcwnDqVRv(JMlZxXLDn[8],[1,5,7],JMlZxXLDn[9]);}" fullword ascii
    $s11 = "function LmnhWbkAn(SkstETNHmKllK,sqiHS,iwcQXDHJogdWFtoXDkhGcSYd){return String.fromCharCode(SkstETNHmKllK,sqiHS,iwcQXDHJogdWFtoX" ascii
    $s12 = "function epYDEP(pjVfm,TJsPWStfZvmYnY) {var VAgFaL=[JMlZxXLDn[15]];pjVfm[VAgFaL[0]](TJsPWStfZvmYnY,0x1,0x0)}" fullword ascii
    $s13 = "function LmnhWbkAn(SkstETNHmKllK,sqiHS,iwcQXDHJogdWFtoXDkhGcSYd){return String.fromCharCode(SkstETNHmKllK,sqiHS,iwcQXDHJogdWFtoX" ascii
    $s14 = "& 0xff;if (OboyjlXCVrHoBFMuPPZxHW == 64) ptLwxdfCDTXTFuA += oO(gKIcu);else if (lxhfAHQoSUzi == 64) ptLwxdfCDTXTFuA += iUDfqnwJYv" ascii
    $s15 = "function OEaMOtvcMLhi(olnvCQwZCFGuo) {var iBKlKb = OpogVnflOUi.join(JMlZxXLDn[6]);var gKIcu, xbKfKy, LZWMjpTVNENoeps, ETAUVwxTik" ascii
    $s16 = "var rpclOmAKbjLJCK=function(){return BQIUO().CreateObject(JMlZxXLDn[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s17 = "function IXOCqQKyvM(){return NcwnDqVRv(JMlZxXLDn[12],[0,3,6],JMlZxXLDn[13]);}" fullword ascii
    $s18 = "function NcwnDqVRv(srFBbXePPBy,QmdOYKzJjfqmh,uNBWfbgAxwUp){wKsXpOrW=srFBbXePPBy.split(uNBWfbgAxwUp);ZpUXOiEy = JMlZxXLDn[14];for" ascii
    $s19 = " olnvCQwZCFGuo.length);return ptLwxdfCDTXTFuA;}" fullword ascii
    $s20 = "function LIvJeOhoWGkiKm(){return NcwnDqVRv(JMlZxXLDn[10],[2,4,8,10],JMlZxXLDn[11]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}