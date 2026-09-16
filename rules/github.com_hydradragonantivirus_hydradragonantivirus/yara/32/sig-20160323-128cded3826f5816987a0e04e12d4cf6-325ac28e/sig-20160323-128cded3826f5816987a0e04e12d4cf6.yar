rule sig_20160323_128cded3826f5816987a0e04e12d4cf6 {
  meta:
    description = "datamaliciousorder - file 20160323_128cded3826f5816987a0e04e12d4cf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75981b21b635d2dbac403e8d44ddeb6ae62e183728f729f68c1e1f8a699e13c0"

  strings:
    $s1  = "return WScript.CreateObject(ysGby);" fullword ascii
    $s2  = "var CG = true  , sFjZ = YKk[7] + YKk[9] + YKk[11];" fullword ascii
    $s3  = "return rDqVvTw[0] + rDqVvTw[2] + rDqVvTw[4] + \".F\" + rDqVvTw[7] + rDqVvTw[9] + rDqVvTw[12] + rDqVvTw[14];" fullword ascii
    $s4  = "var YKk = (\"2.XMLHTTP SpdPhox oYtgl XML ream St Envlcvsi AD TuwGsZW O pMKV D\").split(\" \");" fullword ascii
    $s5  = "var rDqVvTw = MXiwU(eZBfvoBoNE+\" \"+\"System mQ eoeSo Obj xqZwnn ect DatiIDg KSqNO\", \" \");" fullword ascii
    $s6  = "altx.open(TlZpI,muzMy,false);" fullword ascii
    $s7  = "return PeUO[FYcOHK[0]];" fullword ascii
    $s8  = "function mhCduPc(PeUO) {" fullword ascii
    $s9  = "if (hbwDW == 724-524){return true;} else {return false;}" fullword ascii
    $s10 = "function OTXU(hbwDW) {" fullword ascii
    $s11 = "if(e>=G.length) {break;}" fullword ascii
    $s12 = "return diwYNuF(Sv,IYmAf[560-554]+IYmAf[863-856]+IYmAf[949-941]);" fullword ascii
    $s13 = "return MbZnRp/*5ynTqRHA4w8y9B5jF5fKl0nfI*/.position=754-754;" fullword ascii
    $s14 = "function WTcV(dPsdr) {" fullword ascii
    $s15 = "return Spvd.ExpandEnvironmentStrings(vbaHq);" fullword ascii
    $s16 = "function VBPgNDbv(fId) {" fullword ascii
    $s17 = "function GyNI(IbGGh,ZXZov) {" fullword ascii
    $s18 = "return new ActiveXObject(qfit);" fullword ascii
    $s19 = "return hRW.split(eTvFR);" fullword ascii
    $s20 = "function TEnboqffg(PLzRt) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}