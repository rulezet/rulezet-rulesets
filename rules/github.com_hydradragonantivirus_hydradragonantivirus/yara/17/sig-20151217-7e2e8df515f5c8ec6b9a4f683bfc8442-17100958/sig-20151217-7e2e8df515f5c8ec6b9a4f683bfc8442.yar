rule sig_20151217_7e2e8df515f5c8ec6b9a4f683bfc8442 {
  meta:
    description = "datamaliciousorder - file 20151217_7e2e8df515f5c8ec6b9a4f683bfc8442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9004e8aa89b8221c4455c4bf62a25a087e30bab17c3c5c518d7dea452241ee3b"

  strings:
    $s1  = "ow(Math.cos(516), 2) - 1)));} COeIaOAQE[UhqlXZHlBPv]++;}UhqlXZHlBPv++;} return nviGFBfaiEz}" fullword ascii
    $s2  = ") - 1));while(true){if (UhqlXZHlBPv >= (3733+731)/744){break;}COeIaOAQE[UhqlXZHlBPv]=Math.round((Math.pow(Math.sin(876), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(876), 2) - 1)); while(true) { if(COeIaOAQE[UhqlXZHlBPv] > XrnRf[UhqlXZHlBPv].length-(261+55)/316) { break; } if " ascii
    $s4  = "function AbHBmreMiPOWJXtkv(XrnRf){nviGFBfaiEz= '';UhqlXZHlBPv=Math.round((Math.pow(Math.sin(771), 2) + Math.pow(Math.cos(771), 2" ascii
    $s5  = "function AbHBmreMiPOWJXtkv(XrnRf){nviGFBfaiEz= '';UhqlXZHlBPv=Math.round((Math.pow(Math.sin(771), 2) + Math.pow(Math.cos(771), 2" ascii
    $s6  = "function YCpHULl(ByhHCTnFWeqwcKrwPbwOwZUrKeLxoPQKbumA) {return !DtPcoCYpBAJ(DHPHwwDDIhrrwrR(ByhHCTnFWeqwcKrwPbwOwZUrKeLxoPQKbumA" ascii
    $s7  = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s8  = "function YCpHULl(ByhHCTnFWeqwcKrwPbwOwZUrKeLxoPQKbumA) {return !DtPcoCYpBAJ(DHPHwwDDIhrrwrR(ByhHCTnFWeqwcKrwPbwOwZUrKeLxoPQKbumA" ascii
    $s9  = "function B(cTRDdqyXopNG,VhnFtbTDodcGXS){cTRDdqyXopNG.push(VhnFtbTDodcGXS);}" fullword ascii
    $s10 = "function XmsIvhkeIVsJkvHqncdciXketDRfiAblxQJXkKZcimcQhXBKslZowB(UXpokOvZQLEYn,ZPzxLHhOmzNhDX){ return FEUcnXf[mNvqhZrw[VCROk(UXp" ascii
    $s11 = "function A(vyFoKzLYWhYMLL,wCHzQUvwWuHEF,jTctAjyQmRe) {vyFoKzLYWhYMLL[wCHzQUvwWuHEF]=jTctAjyQmRe;}" fullword ascii
    $s12 = "function daKTCrwFFqSZ(djpzLEHHsKztr) {return isFinite(djpzLEHHsKztr);}" fullword ascii
    $s13 = "function ooRyBiQNlbAEsOThS(SXhnVKBaUy,hzfJEOiDiz) {return parseInt(SXhnVKBaUy,hzfJEOiDiz);}" fullword ascii
    $s14 = "function DtPcoCYpBAJ(EEQlmQqmPlNagP) {return isNaN(EEQlmQqmPlNagP);}" fullword ascii
    $s15 = "function DHPHwwDDIhrrwrR(svmwDyLlZucJTvYaOZP) {return parseFloat(svmwDyLlZucJTvYaOZP);}" fullword ascii
    $s16 = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s17 = "X);return HNerT;}" fullword ascii
    $s18 = "function XmsIvhkeIVsJkvHqncdciXketDRfiAblxQJXkKZcimcQhXBKslZowB(UXpokOvZQLEYn,ZPzxLHhOmzNhDX){ return FEUcnXf[mNvqhZrw[VCROk(UXp" ascii
    $s19 = "function VCROk(SZqSLtMwVwR,IWAreseyBegUK,YKhduTlX){SCAq=ooRyBiQNlbAEsOThS(SZqSLtMwVwR,IWAreseyBegUK);HNerT=SCAq.toString(YKhduTl" ascii
    $s20 = "function cKbALmObMkqZUJj(WhunvifqQOlCAmxPR,IkkpSbslaxpmpDsYxBDvsIDPRnWuRxyIBx,UCUNIRuKyGKDMIYQMwqyXJteypNdAJlQxRu){eval(Whunvifq" ascii

  condition:
    uint16(0) == 0x4e6d and
    8 of them
}