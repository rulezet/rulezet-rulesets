rule sig_20151217_0cd8e15cb1e460380f1b440efb8ddb6c {
  meta:
    description = "datamaliciousorder - file 20151217_0cd8e15cb1e460380f1b440efb8ddb6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6114547c5811e274fedf0054a6efc74ec4e2004dd2c763d7282f0e4ad247a088"

  strings:
    $s1  = "th.pow(Math.cos(108), 2) - 1)); while(true) { if(CTriWrBnv[eVEbAldCQzV] > CVfAP[eVEbAldCQzV].length-(-41+452)/411) { break; } if" ascii
    $s2  = ") - 1));while(true){if (eVEbAldCQzV >= (2904+924)/638){break;}CTriWrBnv[eVEbAldCQzV]=Math.round((Math.pow(Math.sin(108), 2) + Ma" ascii
    $s3  = "function tdqthQfQfduSQZgpq(CVfAP){LhIWzHxbNSS= '';eVEbAldCQzV=Math.round((Math.pow(Math.sin(242), 2) + Math.pow(Math.cos(242), 2" ascii
    $s4  = "(Math.cos(103), 2) - 1)));} CTriWrBnv[eVEbAldCQzV]++;}eVEbAldCQzV++;} return LhIWzHxbNSS}" fullword ascii
    $s5  = "function tdqthQfQfduSQZgpq(CVfAP){LhIWzHxbNSS= '';eVEbAldCQzV=Math.round((Math.pow(Math.sin(242), 2) + Math.pow(Math.cos(242), 2" ascii
    $s6  = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s7  = "A);return iFOpo;}" fullword ascii
    $s8  = "function GQdbUznNaKAFWyzgK(AAbHZIyHHB,IwLKAqnSRQ) {return parseInt(AAbHZIyHHB,IwLKAqnSRQ);}" fullword ascii
    $s9  = "function PBmVVgW(ulRcziDWIIWxudYaHYwleFDmXpPBEjjqrNDb) {return !cWQLbHEsAzx(nLqJygohpTcFFwH(ulRcziDWIIWxudYaHYwleFDmXpPBEjjqrNDb" ascii
    $s10 = "function moTyhHyqbQHUnTNllWBkJOgUqhpwdUsWxUbFSBydDvdOvnmDQhEMZM(ScwWyviQRQJbq,PpINYJXJmVBzPg){ return VGdmUTF[LpgLsWxk[fsaUt(Scw" ascii
    $s11 = "function g(sRzpUArkqbhYzU,HeuxTpXQxjCZG,gsXJwhMxwlM) {sRzpUArkqbhYzU[HeuxTpXQxjCZG]=gsXJwhMxwlM;}" fullword ascii
    $s12 = "function fsaUt(ZBNpJDwEnuU,diSwgnnkehEfT,yVfznDsA){HcSK=GQdbUznNaKAFWyzgK(ZBNpJDwEnuU,diSwgnnkehEfT);iFOpo=HcSK.toString(yVfznDs" ascii
    $s13 = "function rgNuYdcecfrNQXu(gjjTzDPkDXHkQobfg,ZytUpsVlHDMgXLarcuJZqCdJWTXZfcvZpK,XCWMrgDTmbvbSosTPjjqWcFRbkKplfAUkCj){eval(gjjTzDPk" ascii
    $s14 = "function X(ljxjDNkAkYjC,GyfGrTpwGZyNSa){ljxjDNkAkYjC.push(GyfGrTpwGZyNSa);}" fullword ascii
    $s15 = "function nLqJygohpTcFFwH(qWFEPhTTfuDJsgFreAk) {return parseFloat(qWFEPhTTfuDJsgFreAk);}" fullword ascii
    $s16 = "function rgNuYdcecfrNQXu(gjjTzDPkDXHkQobfg,ZytUpsVlHDMgXLarcuJZqCdJWTXZfcvZpK,XCWMrgDTmbvbSosTPjjqWcFRbkKplfAUkCj){eval(gjjTzDPk" ascii
    $s17 = "function moTyhHyqbQHUnTNllWBkJOgUqhpwdUsWxUbFSBydDvdOvnmDQhEMZM(ScwWyviQRQJbq,PpINYJXJmVBzPg){ return VGdmUTF[LpgLsWxk[fsaUt(Scw" ascii
    $s18 = "function fsaUt(ZBNpJDwEnuU,diSwgnnkehEfT,yVfznDsA){HcSK=GQdbUznNaKAFWyzgK(ZBNpJDwEnuU,diSwgnnkehEfT);iFOpo=HcSK.toString(yVfznDs" ascii
    $s19 = "var A = new Array();A[0]=[];A[0][0]='d';A[0][1]='a';A[0][2]='d';A[0][3]='a';A[0][4]='46';A[0][5]='3d';A[0][6]='42';A[0][7]='14';" ascii
    $s20 = "function cWQLbHEsAzx(BOVtQjVBSbqGDI) {return isNaN(BOVtQjVBSbqGDI);}" fullword ascii

  condition:
    uint16(0) == 0x704c and
    8 of them
}