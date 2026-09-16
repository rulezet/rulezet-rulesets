rule sig_20151217_d7e789c34d6210cd8a353400486bf1e3 {
  meta:
    description = "datamaliciousorder - file 20151217_d7e789c34d6210cd8a353400486bf1e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d2ac45e38c5841cbc8cf4822e341f0fdd99da6d97867bdf62ab0cd62d49b2ca"

  strings:
    $s1  = "function HQEewpOCebCVRIvMo(zSAxv){OfGnHZscxRT= '';LQQcobIpQFC=Math.round((Math.pow(Math.sin(161), 2) + Math.pow(Math.cos(161), 2" ascii
    $s2  = ") - 1));while(true){if (LQQcobIpQFC >= (1013+949)/327){break;}QKTaVbjPO[LQQcobIpQFC]=Math.round((Math.pow(Math.sin(418), 2) + Ma" ascii
    $s3  = "w(Math.cos(69), 2) - 1)));} QKTaVbjPO[LQQcobIpQFC]++;}LQQcobIpQFC++;} return OfGnHZscxRT}" fullword ascii
    $s4  = "th.pow(Math.cos(418), 2) - 1)); while(true) { if(QKTaVbjPO[LQQcobIpQFC] > zSAxv[LQQcobIpQFC].length-(-257+526)/269) { break; } i" ascii
    $s5  = "function HQEewpOCebCVRIvMo(zSAxv){OfGnHZscxRT= '';LQQcobIpQFC=Math.round((Math.pow(Math.sin(161), 2) + Math.pow(Math.cos(161), 2" ascii
    $s6  = "function VfjrcgG(TEUsFIJrsDKDxPgPXLRszbNJduzOMTPChuWn) {return !oVWfNTmNirx(AoYomXpxtcLPgeh(TEUsFIJrsDKDxPgPXLRszbNJduzOMTPChuWn" ascii
    $s7  = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s8  = "function pAZzP(sjWpKfAjBNf,TCcjxzWRJldim,OtAGbAmV){COGH=gSMAlKtwWOlCpUqmc(sjWpKfAjBNf,TCcjxzWRJldim);ydhAL=COGH.toString(OtAGbAm" ascii
    $s9  = "function VfjrcgG(TEUsFIJrsDKDxPgPXLRszbNJduzOMTPChuWn) {return !oVWfNTmNirx(AoYomXpxtcLPgeh(TEUsFIJrsDKDxPgPXLRszbNJduzOMTPChuWn" ascii
    $s10 = "function mKVJnTnBKoqZxyn(DFAvzJUHmZIjUOcHK,wMBkBpCiRBqQDngXesqocYxBiHwXKgoKNH,vIRYkPimpjIOXDyRDclpsrnxMRAtdBniQYT){eval(DFAvzJUH" ascii
    $s11 = "function AoYomXpxtcLPgeh(LwRMuLDYwitdVAfWSjF) {return parseFloat(LwRMuLDYwitdVAfWSjF);}" fullword ascii
    $s12 = "function zIYSuKfGFtZe(qrseZHZOeMzat) {return isFinite(qrseZHZOeMzat);}" fullword ascii
    $s13 = "function mKVJnTnBKoqZxyn(DFAvzJUHmZIjUOcHK,wMBkBpCiRBqQDngXesqocYxBiHwXKgoKNH,vIRYkPimpjIOXDyRDclpsrnxMRAtdBniQYT){eval(DFAvzJUH" ascii
    $s14 = "function oVWfNTmNirx(DDeDOUrXJvCkPQ) {return isNaN(DDeDOUrXJvCkPQ);}" fullword ascii
    $s15 = "var z = new Array();z[0]=[];z[0][0]='d';z[0][1]='a';z[0][2]='d';z[0][3]='a';z[0][4]='46';z[0][5]='3d';z[0][6]='42';z[0][7]='14';" ascii
    $s16 = "V);return ydhAL;}" fullword ascii
    $s17 = "function U(ELAYYpvpmpEf,EfhLcrvJsWBxlu){ELAYYpvpmpEf.push(EfhLcrvJsWBxlu);}" fullword ascii
    $s18 = "function M(luSkRoTFuzbppp,gTjADqJntiQzy,IFsXSTkDtyP) {luSkRoTFuzbppp[gTjADqJntiQzy]=IFsXSTkDtyP;}" fullword ascii
    $s19 = "function pAZzP(sjWpKfAjBNf,TCcjxzWRJldim,OtAGbAmV){COGH=gSMAlKtwWOlCpUqmc(sjWpKfAjBNf,TCcjxzWRJldim);ydhAL=COGH.toString(OtAGbAm" ascii
    $s20 = "function GzpbBtMqVmWuaYFyGVkQtZhrzeNyVQoOxkBZwmjrLkwnGoGkBcwtCD(jnJtDAIAMWIeJ,WSuAjLdXwGBoYj){ return YniuVIA[KeJLxsPG[pAZzP(jnJ" ascii

  condition:
    uint16(0) == 0x654b and
    8 of them
}