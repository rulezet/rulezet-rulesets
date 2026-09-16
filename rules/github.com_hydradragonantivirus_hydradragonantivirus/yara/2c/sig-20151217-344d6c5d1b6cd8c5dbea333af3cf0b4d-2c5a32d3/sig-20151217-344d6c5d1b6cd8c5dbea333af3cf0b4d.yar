rule sig_20151217_344d6c5d1b6cd8c5dbea333af3cf0b4d {
  meta:
    description = "datamaliciousorder - file 20151217_344d6c5d1b6cd8c5dbea333af3cf0b4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce5b77f3f0f900558bffd8d373d76715e377a565f153d6dc6d2b67d79bbc84af"

  strings:
    $s1  = "function XmtiItfHTPaDayZCu(ynmeT){UCrrbLXKGMl= '';TcCktGaZNPm=Math.round((Math.pow(Math.sin(463), 2) + Math.pow(Math.cos(463), 2" ascii
    $s2  = "th.pow(Math.cos(499), 2) - 1)); while(true) { if(SEyehkijJ[TcCktGaZNPm] > ynmeT[TcCktGaZNPm].length-(-410+920)/510) { break; } i" ascii
    $s3  = ".pow(Math.cos(865), 2) - 1)));} SEyehkijJ[TcCktGaZNPm]++;}TcCktGaZNPm++;} return UCrrbLXKGMl}" fullword ascii
    $s4  = ") - 1));while(true){if (TcCktGaZNPm >= (2494+506)/500){break;}SEyehkijJ[TcCktGaZNPm]=Math.round((Math.pow(Math.sin(499), 2) + Ma" ascii
    $s5  = "wNhfFAwBEdtgtqrsbMtlBdEGnqwYvufovOWK([ynmeT[TcCktGaZNPm][SEyehkijJ[TcCktGaZNPm]]], Math.round((Math.pow(Math.sin(865), 2) + Math" ascii
    $s6  = "function XmtiItfHTPaDayZCu(ynmeT){UCrrbLXKGMl= '';TcCktGaZNPm=Math.round((Math.pow(Math.sin(463), 2) + Math.pow(Math.cos(463), 2" ascii
    $s7  = "function uJtNadb(brqEAjpiWpICkGnwjWxKelMZeOXNrWnVwMeo) {return !RZOhuaszICf(HPJIWTDmuxQLfJa(brqEAjpiWpICkGnwjWxKelMZeOXNrWnVwMeo" ascii
    $s8  = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s9  = "function uJtNadb(brqEAjpiWpICkGnwjWxKelMZeOXNrWnVwMeo) {return !RZOhuaszICf(HPJIWTDmuxQLfJa(brqEAjpiWpICkGnwjWxKelMZeOXNrWnVwMeo" ascii
    $s10 = "L);return bAAlx;}" fullword ascii
    $s11 = "function KlPeFOzAuxSucqT(jYpfMZKQPHHssKoft,oAYXQlFIIIWnBEKnHTjgtmvZxlTRMkHGtJ,hsfEOjCQTrAqKWDVNQwsBUKDMbmyZBrnEcs){eval(jYpfMZKQ" ascii
    $s12 = "function RZOhuaszICf(iKbeOppxmBGNeP) {return isNaN(iKbeOppxmBGNeP);}" fullword ascii
    $s13 = "function NMGjvLjxjYaz(ZaaIcQVUOYSFn) {return isFinite(ZaaIcQVUOYSFn);}" fullword ascii
    $s14 = "function KlPeFOzAuxSucqT(jYpfMZKQPHHssKoft,oAYXQlFIIIWnBEKnHTjgtmvZxlTRMkHGtJ,hsfEOjCQTrAqKWDVNQwsBUKDMbmyZBrnEcs){eval(jYpfMZKQ" ascii
    $s15 = "function H(DHFTLsIeIIHP,lKgbaWavfGzePQ){DHFTLsIeIIHP.push(lKgbaWavfGzePQ);}" fullword ascii
    $s16 = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s17 = "function HuRJq(OlVpcKzhrHL,HkzKtJbYIkYCp,lXiGtiVL){yJEd=bzfWClpzdsAUTSTuM(OlVpcKzhrHL,HkzKtJbYIkYCp);bAAlx=yJEd.toString(lXiGtiV" ascii
    $s18 = "function eMzGUpdGnpNjvnzPfOwNhfFAwBEdtgtqrsbMtlBdEGnqwYvufovOWK(FrBfoVtluErqT,URrkBWksDUfgSX){ return emmCwzu[osSxNgPH[HuRJq(FrB" ascii
    $s19 = "function HPJIWTDmuxQLfJa(ilDRWshbduMUAmOVDLc) {return parseFloat(ilDRWshbduMUAmOVDLc);}" fullword ascii
    $s20 = "function X(AVFbyaJeozrGgl,GzJEfLKINWnGi,UjxYBVlbMoR) {AVFbyaJeozrGgl[GzJEfLKINWnGi]=UjxYBVlbMoR;}" fullword ascii

  condition:
    uint16(0) == 0x736f and
    8 of them
}