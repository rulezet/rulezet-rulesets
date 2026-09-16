rule sig_20151216_7c36a4bf435b1cadf7b4cf4f2a6bb961 {
  meta:
    description = "datamaliciousorder - file 20151216_7c36a4bf435b1cadf7b4cf4f2a6bb961.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eefbac7ac401ca41934d4571f7b15840fd9f0f7cfed47a8e9404164ab5c8ef84"

  strings:
    $s1  = "th.pow(Math.cos(877), 2) - 1)); while(true) { if(OsTBUmMQp[HLlfahqkaGI] > JjOXE[HLlfahqkaGI].length-(559+317)/876) { break; } if" ascii
    $s2  = "w(Math.cos(925), 2) - 1)));} OsTBUmMQp[HLlfahqkaGI]++;}HLlfahqkaGI++;} return nYwAZLQHLMl}" fullword ascii
    $s3  = "function FuQkgCQtAjUjJqnzt(JjOXE){nYwAZLQHLMl= '';HLlfahqkaGI=Math.round((Math.pow(Math.sin(559), 2) + Math.pow(Math.cos(559), 2" ascii
    $s4  = ") - 1));while(true){if (HLlfahqkaGI >= (1306+182)/248){break;}OsTBUmMQp[HLlfahqkaGI]=Math.round((Math.pow(Math.sin(877), 2) + Ma" ascii
    $s5  = "function FuQkgCQtAjUjJqnzt(JjOXE){nYwAZLQHLMl= '';HLlfahqkaGI=Math.round((Math.pow(Math.sin(559), 2) + Math.pow(Math.cos(559), 2" ascii
    $s6  = "function wrHuhng(xfGpIuqosAwkzpeZNxbRiKXUviEndFyIznpb) {return !zFsiiiGuMZd(IrWRojzyyAXkSKn(xfGpIuqosAwkzpeZNxbRiKXUviEndFyIznpb" ascii
    $s7  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s8  = "function PeiHCrUkrIkgcFHSbdnxoErZilxJuNtbZYtQturHNgRZZcEMjEbEzc(ltRHHHvQQtukE,IZskGowCEiSSWG){ return PALedEH[YxvUSRUS[hXgfY(ltR" ascii
    $s9  = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s10 = "function wrHuhng(xfGpIuqosAwkzpeZNxbRiKXUviEndFyIznpb) {return !zFsiiiGuMZd(IrWRojzyyAXkSKn(xfGpIuqosAwkzpeZNxbRiKXUviEndFyIznpb" ascii
    $s11 = "function L(qjvPzBIoWoYlJG,ykFBjUVUMppAI,ZHvKmcqdOih) {qjvPzBIoWoYlJG[ykFBjUVUMppAI]=ZHvKmcqdOih;}" fullword ascii
    $s12 = "function xDEPHfvpTmJP(dgmOgBqYJGpSZ) {return isFinite(dgmOgBqYJGpSZ);}" fullword ascii
    $s13 = "function TqyVXLtFBTFaubaqp(CDrBkhGnJC,sXGmWTczpY) {return parseInt(CDrBkhGnJC,sXGmWTczpY);}" fullword ascii
    $s14 = "function IrWRojzyyAXkSKn(urxnYtGGXLDAeOkMVJY) {return parseFloat(urxnYtGGXLDAeOkMVJY);}" fullword ascii
    $s15 = "function zFsiiiGuMZd(fSBULHuvdQLHFJ) {return isNaN(fSBULHuvdQLHFJ);}" fullword ascii
    $s16 = "function hXgfY(qSsZLLQZLpS,ScpAdtcNdNiLI,bqASPGSi){vUbi=TqyVXLtFBTFaubaqp(qSsZLLQZLpS,ScpAdtcNdNiLI);JsizL=vUbi.toString(bqASPGS" ascii
    $s17 = "i);return JsizL;}" fullword ascii
    $s18 = "function hXgfY(qSsZLLQZLpS,ScpAdtcNdNiLI,bqASPGSi){vUbi=TqyVXLtFBTFaubaqp(qSsZLLQZLpS,ScpAdtcNdNiLI);JsizL=vUbi.toString(bqASPGS" ascii
    $s19 = "function PeiHCrUkrIkgcFHSbdnxoErZilxJuNtbZYtQturHNgRZZcEMjEbEzc(ltRHHHvQQtukE,IZskGowCEiSSWG){ return PALedEH[YxvUSRUS[hXgfY(ltR" ascii
    $s20 = "function T(GRjEKcbUDZiA,jckXmTYpbcUWZu){GRjEKcbUDZiA.push(jckXmTYpbcUWZu);}" fullword ascii

  condition:
    uint16(0) == 0x7859 and
    8 of them
}