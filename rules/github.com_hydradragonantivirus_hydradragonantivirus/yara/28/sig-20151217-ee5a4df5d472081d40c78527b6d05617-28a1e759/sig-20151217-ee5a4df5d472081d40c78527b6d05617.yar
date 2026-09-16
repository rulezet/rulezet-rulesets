rule sig_20151217_ee5a4df5d472081d40c78527b6d05617 {
  meta:
    description = "datamaliciousorder - file 20151217_ee5a4df5d472081d40c78527b6d05617.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f50328670acef767a6354c86e96b50c89b06253cecd9f4bd5ce38b71f2bb4d2"

  strings:
    $s1  = ".pow(Math.cos(884), 2) - 1)));} hEjBDNRtQ[fZGvIClYZqt]++;}fZGvIClYZqt++;} return tJbVFlahlid}" fullword ascii
    $s2  = "th.pow(Math.cos(178), 2) - 1)); while(true) { if(hEjBDNRtQ[fZGvIClYZqt] > HSeDG[fZGvIClYZqt].length-(-194+818)/624) { break; } i" ascii
    $s3  = "function cSbWNlMBUNZcWzoqA(HSeDG){tJbVFlahlid= '';fZGvIClYZqt=Math.round((Math.pow(Math.sin(555), 2) + Math.pow(Math.cos(555), 2" ascii
    $s4  = ") - 1));while(true){if (fZGvIClYZqt >= (4909+461)/895){break;}hEjBDNRtQ[fZGvIClYZqt]=Math.round((Math.pow(Math.sin(178), 2) + Ma" ascii
    $s5  = "DgSWFYmZvjaVYlIlRPoTsxqSnNfPffVBtDrG([HSeDG[fZGvIClYZqt][hEjBDNRtQ[fZGvIClYZqt]]], Math.round((Math.pow(Math.sin(884), 2) + Math" ascii
    $s6  = "function cSbWNlMBUNZcWzoqA(HSeDG){tJbVFlahlid= '';fZGvIClYZqt=Math.round((Math.pow(Math.sin(555), 2) + Math.pow(Math.cos(555), 2" ascii
    $s7  = "function tNPAmwD(xvkXtKVzRlxGFpipKpkRNuUkXgAsSuZajYcg) {return !XjTrEtCPbbC(KVVkbnucvakcoGb(xvkXtKVzRlxGFpipKpkRNuUkXgAsSuZajYcg" ascii
    $s8  = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s9  = "function tNPAmwD(xvkXtKVzRlxGFpipKpkRNuUkXgAsSuZajYcg) {return !XjTrEtCPbbC(KVVkbnucvakcoGb(xvkXtKVzRlxGFpipKpkRNuUkXgAsSuZajYcg" ascii
    $s10 = "function rFYTRuwqeYchMpXRLiDgSWFYmZvjaVYlIlRPoTsxqSnNfPffVBtDrG(HoWLnBiDIfiqf,bgTvwblFXhgDDi){ return KjFexez[RXYzMUTZ[qQfsy(HoW" ascii
    $s11 = "function KVVkbnucvakcoGb(BfSIgaPGEpkKNayuHjW) {return parseFloat(BfSIgaPGEpkKNayuHjW);}" fullword ascii
    $s12 = "function NJHnUIkjwcfZ(orkWqcODAetTv) {return isFinite(orkWqcODAetTv);}" fullword ascii
    $s13 = "function YjcQolkYZbFAnuW(jwUpCMGMUaBoIqrgJ,rYQNJBiTMYDzVBfaEOxlGbaaEtuTuKMoyi,YKEdxQhAQDrwMdDENGDFyCcdgnMLeBLQwTt){eval(jwUpCMGM" ascii
    $s14 = "function rFYTRuwqeYchMpXRLiDgSWFYmZvjaVYlIlRPoTsxqSnNfPffVBtDrG(HoWLnBiDIfiqf,bgTvwblFXhgDDi){ return KjFexez[RXYzMUTZ[qQfsy(HoW" ascii
    $s15 = "function qQfsy(RIrRtvYIYaG,bUMUoOYsPbRrl,heroXsSm){Xcoz=XxcfpwZfvHHxOooxr(RIrRtvYIYaG,bUMUoOYsPbRrl);jJvYv=Xcoz.toString(heroXsS" ascii
    $s16 = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s17 = "function XjTrEtCPbbC(wIZaDiQiWunuoE) {return isNaN(wIZaDiQiWunuoE);}" fullword ascii
    $s18 = "function XxcfpwZfvHHxOooxr(OZUGohitNe,dZqfIviMNo) {return parseInt(OZUGohitNe,dZqfIviMNo);}" fullword ascii
    $s19 = "function qQfsy(RIrRtvYIYaG,bUMUoOYsPbRrl,heroXsSm){Xcoz=XxcfpwZfvHHxOooxr(RIrRtvYIYaG,bUMUoOYsPbRrl);jJvYv=Xcoz.toString(heroXsS" ascii
    $s20 = "function k(NkbcWxNClrzU,McDbOMLbzhJRFn){NkbcWxNClrzU.push(McDbOMLbzhJRFn);}" fullword ascii

  condition:
    uint16(0) == 0x5852 and
    8 of them
}