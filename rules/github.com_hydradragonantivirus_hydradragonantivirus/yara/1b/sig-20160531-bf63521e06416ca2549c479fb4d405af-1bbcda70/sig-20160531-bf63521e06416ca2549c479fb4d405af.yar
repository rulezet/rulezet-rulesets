rule sig_20160531_bf63521e06416ca2549c479fb4d405af {
  meta:
    description = "datamaliciousorder - file 20160531_bf63521e06416ca2549c479fb4d405af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1b42fa16736b3bdeb60e6aa46313e1b8d99901703e422b1ecd9a37279774ee8"

  strings:
    $s1  = "var rRphPKiWhM=function(){return WScript.CreateObject(vkfZEHpriwtvXIjsys[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function BrClXlN(auXnBoaED,MhNYQwYFWLlVnXwYLxdOjpN){return auXnBoaED.charAt(MhNYQwYFWLlVnXwYLxdOjpN);}" fullword ascii
    $s3  = "MQis=0;BcKUbqSBNMQis<FSywtfeZJw.length;BcKUbqSBNMQis++) {MAzWbdiw+=TEFaTMfAeTbj[FSywtfeZJw[BcKUbqSBNMQis]];}return MAzWbdiw.subs" ascii
    $s4  = "function kPkxl(qhLHkIkVbvfYriNOydNP,MuZuleYSLrOUlMVOeIKkFb){return String.fromCharCode(qhLHkIkVbvfYriNOydNP,MuZuleYSLrOUlMVOeIKk" ascii
    $s5  = "(XbDVlwqPiswuu,0x1,0x0)}function xlbBOf(xTlqM,bdZcYjvnNW,QKBQkgcWVZL){var nCcvspjzR=xTlqM.createtextfile(bdZcYjvnNW,true);nCcvsp" ascii
    $s6  = "(XbDVlwqPiswuu,0x1,0x0)}function xlbBOf(xTlqM,bdZcYjvnNW,QKBQkgcWVZL){var nCcvspjzR=xTlqM.createtextfile(bdZcYjvnNW,true);nCcvsp" ascii
    $s7  = "function jXhQFEpiIwYM(DksmioEMotftY) {var ctMdKRxCfQjQOcydkxS = XoLmmauuBlQLhOLSVONX.join(vkfZEHpriwtvXIjsys[7]);var CytqYYGswRl" ascii
    $s8  = "function dTqqAqXmVDXWCw(){return rRphPKiWhM.ExpandEnvironmentStrings(DnEcwdjqTusFLV())}" fullword ascii
    $s9  = "function cDUfGBM(vckqHSwbYWcVlZ,XbDVlwqPiswuu) {var fULSXUCrwy=[vkfZEHpriwtvXIjsys[15]];vckqHSwbYWcVlZ[fULSXUCrwy[0]]" fullword ascii
    $s10 = "function LEFQvoFdBiJLGLJaptrL(AEnQnY,wGiorBY,plXDt){return String.fromCharCode(AEnQnY,wGiorBY,plXDt);}" fullword ascii
    $s11 = "function DnEcwdjqTusFLV(){return YYHBhe(vkfZEHpriwtvXIjsys[9],[1,5,7],vkfZEHpriwtvXIjsys[10]);}" fullword ascii
    $s12 = "function NHfTghjbhGCBSwIlsnUzrwfC(EIDQUlsUl,MivSTLZOiiVNR){return EIDQUlsUl.indexOf(MivSTLZOiiVNR);}" fullword ascii
    $s13 = "var LCMGiMNdA=function(){return new ActiveXObject(vkfZEHpriwtvXIjsys[1]);}();" fullword ascii
    $s14 = "function xHIyh(){return YYHBhe(vkfZEHpriwtvXIjsys[11],[2,4,8,10],vkfZEHpriwtvXIjsys[12]);}" fullword ascii
    $s15 = "function YYHBhe(AJtDe,FSywtfeZJw,iviaiWgoGx){TEFaTMfAeTbj=AJtDe.split(iviaiWgoGx);MAzWbdiw = vkfZEHpriwtvXIjsys[0];for(BcKUbqSBN" ascii
    $s16 = "function kPkxl(qhLHkIkVbvfYriNOydNP,MuZuleYSLrOUlMVOeIKkFb){return String.fromCharCode(qhLHkIkVbvfYriNOydNP,MuZuleYSLrOUlMVOeIKk" ascii
    $s17 = "le (BwKykJAZRTvlLvkxST < DksmioEMotftY.length);return tVFhypZu;}" fullword ascii
    $s18 = "function Wu(evJXUhJBkvXXmiBYIRXFTYkJ){return String.fromCharCode(evJXUhJBkvXXmiBYIRXFTYkJ);}" fullword ascii
    $s19 = "UROTQMCd == 64) tVFhypZu += Wu(CytqYYGswRlGBeSdwZy);else if (ozFJCYO == 64) tVFhypZu += kPkxl(CytqYYGswRlGBeSdwZy, aGooEvTTQBSwK" ascii
    $s20 = "function YYHBhe(AJtDe,FSywtfeZJw,iviaiWgoGx){TEFaTMfAeTbj=AJtDe.split(iviaiWgoGx);MAzWbdiw = vkfZEHpriwtvXIjsys[0];for(BcKUbqSBN" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}