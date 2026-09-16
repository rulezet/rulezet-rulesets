rule sig_20151011_3b6d0b8c161637cbc7cd016dfe042d41 {
  meta:
    description = "datamaliciousorder - file 20151011_3b6d0b8c161637cbc7cd016dfe042d41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a43433b0ee16bdb264ba045845655d17c7653911f21ae7ea6719172c61db5010"

  strings:
    $s1  = "var str=\"5551575E060B0300050A240C160A0111160B14014A070B095E225E0805001D0D0A05090B160510054A070B095E17011614565E5550505051575452" ascii
    $s2  = "r += '652'; }; function isdu() { lvkr += 'gth; '; }; function vwlf() { lvkr += '.com'; }; function nnlz() { lvkr += '0000)'; }; " ascii
    $s3  = "q() { lvkr += 'ate ='; }; function fpm() { lvkr += 'read'; }; function pfzi() { lvkr += '; xa'; }; function hgdo() { lvkr += 're" ascii
    $s4  = "}; function wnyv() { lvkr += 'ar'; }; function tfo() { lvkr += 'ready'; }; function jbrc() { lvkr += '; dl'; }; function zav() {" ascii
    $s5  = "755\"; function znzo() { lvkr += ' = '; }; function xbqe() { lvkr += 'op'; }; function kwt() { lvkr += 'LHTTP'; }; function pyjl" ascii
    $s6  = ") { lvkr += 'cr'; }; function eyk() { lvkr += ' var '; }; function mhfs() { lvkr += 'b.len'; }; function dyt() { lvkr += '; '; }" ascii
    $s7  = "3);'; }; function jaz() { lvkr += ' 1;'; }; function lzug() { lvkr += 't.Cre'; }; function otlm() { lvkr += 'g.'; }; function rf" ascii
    $s8  = "r '; }; function bjct() { lvkr += '\".spl'; }; function ttbg() { lvkr += 'T\"'; }; function bft() { lvkr += 'rn'; }; function pr" ascii
    $s9  = "{ lvkr += 'en'; }; function ubw() { lvkr += ' { w'; }; function viz() { lvkr += 'n,'; }; function rnhy() { lvkr += 'i<'; }; func" ascii
    $s10 = ") { lvkr += '; '; }; function qibm() { lvkr += 'Cha'; }; function bgc() { lvkr += 'th'; }; function gah() { lvkr += '+\"/co'; };" ascii
    $s11 = "y() { lvkr += ' xa.'; }; function vmlo() { lvkr += '+\".'; }; function zgu() { lvkr += ' { '; }; function uhzi() { lvkr += 's ';" ascii
    $s12 = "'; }; function hrc() { lvkr += 'espon'; }; function xsb() { lvkr += '\");'; }; function jaib() { lvkr += 'on '; }; function ndjp" ascii
    $s13 = "ion wgtk() { lvkr += ' x'; }; function qcjr() { lvkr += 'xa.si'; }; function ajd() { lvkr += 'a.'; }; function rqy() { lvkr += '" ascii
    $s14 = "tion kkm() { lvkr += 'fu'; }; function ccl() { lvkr += 'WS'; }; function bpzv() { lvkr += 'Bo'; }; function uqru() { lvkr += 'je" ascii
    $s15 = "kr += ' {}'; }; function hil() { lvkr += 'ar'; }; function mphn() { lvkr += 'Math'; }; function fga() { lvkr += 'htt'; }; functi" ascii
    $s16 = "; frku(); ghi(); axt(); upd(); hlq(); hhd(); otlm(); sxo(); qibm(); zfvo(); lots(); ybmt(); bgc(); lcg(); wjgi(); hiwe(); mphn()" ascii
    $s17 = "kr += 'nsze'; }; function wwhx() { lvkr += '\"+fr,'; }; function dvs() { lvkr += 'for'; }; function cmay() { lvkr += '; };'; }; " ascii
    $s18 = "ion ytgc() { lvkr += 'tatec'; }; function qnpp() { lvkr += 'str'; }; function bjom() { lvkr += 'h '; }; function wmw() { lvkr +=" ascii
    $s19 = ";'; }; function mpw() { lvkr += 'n ='; }; function jyqb() { lvkr += 'teObj'; }; function frku() { lvkr += 'ings'; }; function dr" ascii
    $s20 = ") { lvkr += 'try {'; }; function wyd() { lvkr += 'Scri'; }; function kvo() { lvkr += 'nd();'; }; function rii() { lvkr += 'pen';" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}