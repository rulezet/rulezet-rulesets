rule sig_20150924_d096df3142ff2b506c962cc434883682 {
  meta:
    description = "datamaliciousorder - file 20150924_d096df3142ff2b506c962cc434883682.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9abb84f4a995c7572257d898ee2158d0df806a58b4f1586da87a8c1b8e7ad2b2"

  strings:
    $s1  = "var str=\"5550525E0B14011605100D0B0A17240C160A0111160B14014A070B09\";function dpfmfut() { njhgda += 'TTP\"'; }; function iwwy() " ascii
    $s2  = "jhgda += ' = ws'; }; function eoqaeh() { njhgda += 's.Run'; }; function gneb() { njhgda += '& xo.'; }; function salzuno() { njhg" ascii
    $s3  = "}; function dhqx() { njhgda += '\"GET'; }; function juzzx() { njhgda += 'iveX'; }; function ozkl() { njhgda += '+) '; }; functio" ascii
    $s4  = " += '; if '; }; function lgyq() { njhgda += 'xa.'; }; function xrwbjj() { njhgda += 'n('; }; function mhli() { njhgda += 't.She'" ascii
    $s5  = "}; function qtee() { njhgda += '.ope'; }; function vkvxiy() { njhgda += '; } '; }; function uxfbcu() { njhgda += 'it'; }; functi" ascii
    $s6  = " 'com i'; }; function najlx() { njhgda += 'ta'; }; function hahtmrd() { njhgda += 'ML2'; }; function vgtgmu() { njhgda += 'ht'; " ascii
    $s7  = "on kvfafu() { njhgda += 'B.Str'; }; function tlksyvd() { njhgda += '0; xa'; }; function leeolt() { njhgda += '(xo'; }; function " ascii
    $s8  = "() { njhgda += 'Bod'; }; function owwso() { njhgda += '.onr'; }; function novtn() { njhgda += '} c'; }; function fljtws() { njhg" ascii
    $s9  = " }; function gtqhbrj() { njhgda += 'ct('; }; function ncbswp() { njhgda += '= 1'; }; function fulmabp() { njhgda += '{}'; }; fun" ascii
    $s10 = "reksb() { njhgda += 'ar'; }; function vofafg() { njhgda += 'ak;'; }; function xkhk() { njhgda += 'ten.'; }; function ormu() { nj" ascii
    $s11 = "jhgda += 'dE'; }; function hyugyv() { njhgda += 'var b'; }; function mfozami() { njhgda += '{ var'; }; function rtyybq() { njhgd" ascii
    $s12 = "anbcxzd() { njhgda += 'xa.c'; }; function qvxctk() { njhgda += '+\"/do'; }; function umwndrj() { njhgda += 'e = '; }; function f" ascii
    $s13 = "ion qilwsou() { njhgda += 'e()'; }; function ktjmcsj() { njhgda += 'd=\"+'; }; function lvfc() { njhgda += '71);'; }; function s" ascii
    $s14 = "i() { njhgda += 'dl'; }; function dybe() { njhgda += ' Acti'; }; function iulsic() { njhgda += '(xa'; }; function dirg() { njhgd" ascii
    $s15 = "jhgda += 'rando'; }; function ldwvdtq() { njhgda += 'veX'; }; function mmcfbj() { njhgda += 'ToFi'; }; function emmf() { njhgda " ascii
    $s16 = "}; function apqvv() { njhgda += 'ea'; }; function uzkph() { njhgda += ' Act'; }; function prho() { njhgda += 'nvir'; }; function" ascii
    $s17 = "on rcet() { njhgda += '= n'; }; function gkowq() { njhgda += 'te =='; }; function awxfci() { njhgda += 'nt.ph'; }; function gwuv" ascii
    $s18 = " += 'n =='; }; function bdnzqt() { njhgda += 'xa.wr'; }; function izqhae() { njhgda += '); '; }; function vdntg() { njhgda += 'e" ascii
    $s19 = "; function patmi() { njhgda += '.XMLH'; }; function idzo() { njhgda += '\")+'; }; function xhnes() { njhgda += '\"sexy'; }; func" ascii
    $s20 = "'; }; function vcsrkl() { njhgda += 'xo'; }; function ipfm() { njhgda += '}; '; }; function dnxh() { njhgda += 'Strin'; }; funct" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}