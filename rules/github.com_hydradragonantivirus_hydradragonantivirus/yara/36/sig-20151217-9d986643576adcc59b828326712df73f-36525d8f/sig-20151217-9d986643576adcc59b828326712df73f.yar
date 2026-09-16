rule sig_20151217_9d986643576adcc59b828326712df73f {
  meta:
    description = "datamaliciousorder - file 20151217_9d986643576adcc59b828326712df73f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e507cb8ac9c17ab90ebabe66bff9069db502f3f82801b35eda1db4a309615771"

  strings:
    $s1  = "function ZBHdgxzbbNHghjJvq(NKCxP){GVDFGDAIBcJ= '';HHhZAdNaEwN=Math.round((Math.pow(Math.sin(982), 2) + Math.pow(Math.cos(982), 2" ascii
    $s2  = "pow(Math.cos(623), 2) - 1)));} UUfDUryIY[HHhZAdNaEwN]++;}HHhZAdNaEwN++;} return GVDFGDAIBcJ}" fullword ascii
    $s3  = ") - 1));while(true){if (HHhZAdNaEwN >= (4639+605)/874){break;}UUfDUryIY[HHhZAdNaEwN]=Math.round((Math.pow(Math.sin(156), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(156), 2) - 1)); while(true) { if(UUfDUryIY[HHhZAdNaEwN] > NKCxP[HHhZAdNaEwN].length-(550+284)/834) { break; } if" ascii
    $s5  = "OkgKzWLuCyViqIIhNccUFEmbPuPXAqZlXYE([NKCxP[HHhZAdNaEwN][UUfDUryIY[HHhZAdNaEwN]]], Math.round((Math.pow(Math.sin(623), 2) + Math." ascii
    $s6  = "function ZBHdgxzbbNHghjJvq(NKCxP){GVDFGDAIBcJ= '';HHhZAdNaEwN=Math.round((Math.pow(Math.sin(982), 2) + Math.pow(Math.cos(982), 2" ascii
    $s7  = "function dRuegnV(SWpdEbdeZjRIYDXPtpfENlAiAPZMysRkSUpb) {return !FkrAwwGpmUH(ORIarZdUetGgazj(SWpdEbdeZjRIYDXPtpfENlAiAPZMysRkSUpb" ascii
    $s8  = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s9  = "function B(WJSJJtKGMxSB,oCbOuajoIsNqid){WJSJJtKGMxSB.push(oCbOuajoIsNqid);}" fullword ascii
    $s10 = "function MafgL(UDeQTkObxCR,ibSTuetUrIiLZ,meEAyvLU){pdDr=svYHXFWsInVvYVPvm(UDeQTkObxCR,ibSTuetUrIiLZ);ROCtk=pdDr.toString(meEAyvL" ascii
    $s11 = "function pQkyropUZPpyYixwrxtOkgKzWLuCyViqIIhNccUFEmbPuPXAqZlXYE(BdVSnmGRheEqb,oNeVUXTCUGTMmD){ return uPvysCv[lzAXCeLF[MafgL(BdV" ascii
    $s12 = "function MafgL(UDeQTkObxCR,ibSTuetUrIiLZ,meEAyvLU){pdDr=svYHXFWsInVvYVPvm(UDeQTkObxCR,ibSTuetUrIiLZ);ROCtk=pdDr.toString(meEAyvL" ascii
    $s13 = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s14 = "function pQkyropUZPpyYixwrxtOkgKzWLuCyViqIIhNccUFEmbPuPXAqZlXYE(BdVSnmGRheEqb,oNeVUXTCUGTMmD){ return uPvysCv[lzAXCeLF[MafgL(BdV" ascii
    $s15 = "function ORIarZdUetGgazj(flwKHurkjlhoiXooftA) {return parseFloat(flwKHurkjlhoiXooftA);}" fullword ascii
    $s16 = "function dRuegnV(SWpdEbdeZjRIYDXPtpfENlAiAPZMysRkSUpb) {return !FkrAwwGpmUH(ORIarZdUetGgazj(SWpdEbdeZjRIYDXPtpfENlAiAPZMysRkSUpb" ascii
    $s17 = "function GVSSvEzytITBbih(EUGzuzSlYPfUrFWcQ,qmJNNyqEsRzDcdATxwJkZtyHhOeJiXDQrU,yJsykblYKaCuZDJcXXXhmaBojutTmRPoaAz){eval(EUGzuzSl" ascii
    $s18 = "function FkrAwwGpmUH(KrnLnBaKxkpPbI) {return isNaN(KrnLnBaKxkpPbI);}" fullword ascii
    $s19 = "function L(LRikQXkhGnomnQ,NRdxVaMNlDRzt,rShbrrgNlgB) {LRikQXkhGnomnQ[NRdxVaMNlDRzt]=rShbrrgNlgB;}" fullword ascii
    $s20 = "function svYHXFWsInVvYVPvm(STcvgWAnnr,UKgmmOqEgd) {return parseInt(STcvgWAnnr,UKgmmOqEgd);}" fullword ascii

  condition:
    uint16(0) == 0x7a6c and
    8 of them
}