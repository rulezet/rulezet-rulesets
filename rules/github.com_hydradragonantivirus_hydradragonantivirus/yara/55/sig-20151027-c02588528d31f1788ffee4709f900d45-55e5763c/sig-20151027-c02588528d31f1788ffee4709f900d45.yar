rule sig_20151027_c02588528d31f1788ffee4709f900d45 {
  meta:
    description = "datamaliciousorder - file 20151027_c02588528d31f1788ffee4709f900d45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76edc61e582c5ddc774d56789b3c620c1e29dc2809b3acce687641bc01881838"

  strings:
    $s1  = "var str=\"5552545E080B1D0508101D240C160A0111160B14014A070B095E305E050F0D0A004A0A085E17565E555050515D53525155535E55\"; function p" ascii
    $s2  = "gj += 'var '; }; function loh() { dgj += 'a.ope'; }; function knek() { dgj += 'SXML2'; }; function ryh() { dgj += '2); t'; }; fu" ascii
    $s3  = "+= '.linc'; }; function wpn() { dgj += 'tes.'; }; function objv() { dgj += ' n<=3'; }; function pwqj() { dgj += 'LHTTP'; }; func" ascii
    $s4  = "n fbme() { dgj += 'a.org'; }; function ozi() { dgj += 't.C'; }; function xlil() { dgj += 'y); '; }; function aiyb() { dgj += ' w" ascii
    $s5  = "function yviu() { dgj += 'th; '; }; function ghs() { dgj += 'Run('; }; function visx() { dgj += '117'; };axob(); vvay(); heko();" ascii
    $s6  = "('; }; function uia() { dgj += 'n = '; }; function spen() { dgj += 'ar'; }; function srun() { dgj += 'teOb'; }; function hcck() " ascii
    $s7  = "ion ega() { dgj += '; '; }; function qruf() { dgj += 'o.sta'; }; function qazp() { dgj += 'a.ty'; }; function yle() { dgj += 'ng" ascii
    $s8  = "function cvtz() { dgj += 'com'; }; function pwg() { dgj += '.s'; }; function aab() { dgj += 'i++'; }; function rnwd() { dgj += '" ascii
    $s9  = "}; function gxbb() { dgj += 'WSc'; }; function jkgm() { dgj += 'a.pos'; }; function mfls() { dgj += ' x'; }; function axob() { d" ascii
    $s10 = "'; }; function anaj() { dgj += ' ('; }; function vtt() { dgj += 'o.se'; }; function ilw() { dgj += '.clo'; }; function zte() { d" ascii
    $s11 = "ction pigt() { dgj += 'men'; }; function qcx() { dgj += 'if'; }; function ulkv() { dgj += 't.Cr'; }; function zxb() { dgj += 'fa" ascii
    $s12 = "mvr() { ygnh(dgj); };  function dpbs() { dgj += 'jec'; }; var dgj = ''; function zmh() { dgj += '.St'; }; function aohi() { dgj " ascii
    $s13 = " '= WS'; }; function sxai() { dgj += 'ript'; }; function ftf() { dgj += 'spl'; }; function tbsv() { dgj += '.C'; }; function abe" ascii
    $s14 = "o() { dgj += 'a.'; }; function sfxz() { dgj += ' i; b'; }; function uisr() { dgj += 'teOb'; }; function bsb() { dgj += 'res'; };" ascii
    $s15 = " ' 1'; }; function dizm() { dgj += 'oun'; }; function igw() { dgj += 'on'; }; function npf() { dgj += 'id=\"'; }; function vhne(" ascii
    $s16 = "); pyj(); qpme(); rmc(); vzd(); dizm(); lilt(); npf(); rjq(); sbkf(); nbw(); visx(); enyo(); cstu(); zxb(); hsr(); fbwz(); vtt()" ascii
    $s17 = "; function pmc() { dgj += 'ch'; }; function eas() { dgj += 'ci'; }; function nkl() { dgj += ') { v'; }; function gskd() { dgj +=" ascii
    $s18 = "on zuzx() { dgj += ') {'; }; function rjq() { dgj += '+s'; }; function bjo() { dgj += 'ea'; }; function qxqz() { dgj += 'rom'; }" ascii
    $s19 = "gj += ' xo'; }; function btlv() { dgj += ' ld ='; }; function rbb() { dgj += '1,0);'; }; function hpw() { dgj += '); '; }; funct" ascii
    $s20 = "gj += 'l\"); '; }; function fdoa() { dgj += 'cript'; }; function vxo() { dgj += 've'; }; function xvic() { dgj += '.le'; }; func" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}