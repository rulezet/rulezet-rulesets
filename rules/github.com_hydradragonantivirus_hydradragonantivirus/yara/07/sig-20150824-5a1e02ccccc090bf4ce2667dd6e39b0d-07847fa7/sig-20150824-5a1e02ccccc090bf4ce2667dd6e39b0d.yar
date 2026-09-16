rule sig_20150824_5a1e02ccccc090bf4ce2667dd6e39b0d {
  meta:
    description = "datamaliciousorder - file 20150824_5a1e02ccccc090bf4ce2667dd6e39b0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "529597c4d2fc18f7fb4e89af745707757ad4948c637dfc23956c66a03dc74fb3"

  strings:
    $s1  = "var stroke=\"5557545E0905160F01100D0A03240C160A0111160B14014A070B09\";function j205() { flgl('php?'); return qpb(); };  function" ascii
    $s2  = "gl('() { '); return qpb(); };  function j196() { flgl('GET'); return qpb(); };  function j215() { flgl('); x'); return qpb(); };" ascii
    $s3  = "{ flgl('ll\"'); return qpb(); };  function j20() { flgl('com '); return qpb(); };  function j185() { flgl('; };'); return qpb();" ascii
    $s4  = "  function j127() { flgl(') { '); return qpb(); };  function j107() { flgl('o.onr'); return qpb(); };  function j48() { flgl('he" ascii
    $s5  = " { flgl('2.XM'); return qpb(); };  function j122() { flgl('4 && '); return qpb(); };  function j207() { flgl('d=\"+f'); return q" ascii
    $s6  = "  function j135() { flgl('OD'); return qpb(); };  function j216() { flgl('o.s'); return qpb(); };  function j16() { flgl('com');" ascii
    $s7  = " return qpb(); };  function j45() { flgl('\"WSc'); return qpb(); };  function j33() { flgl('b.len'); return qpb(); };  function " ascii
    $s8  = " { flgl('; }; '); return qpb(); };  function j194() { flgl('.ope'); return qpb(); };  var ol = ''; var zw = '';  function j49() " ascii
    $s9  = "n j74() { flgl('und('); return qpb(); };  function j164() { flgl('sitio'); return qpb(); };  function j11() { flgl('read'); retu" ascii
    $s10 = ";  function j38() { flgl(' w'); return qpb(); };  function j41() { flgl('ct'); return qpb(); };  function j230() { flgl('dl('); " ascii
    $s11 = "nction j22() { flgl('ecur'); return qpb(); };  function flgl(uran) { zw = uran; };  function j204() { flgl('nt.'); return qpb();" ascii
    $s12 = "n j37() { flgl('ar'); return qpb(); };  function j4() { flgl('l('); return qpb(); };  function j130() { flgl('ew A'); return qpb" ascii
    $s13 = "ec'); return qpb(); };  function j71() { flgl('92)+'); return qpb(); };  function j118() { flgl('ea'); return qpb(); };  functio" ascii
    $s14 = " };  function j101() { flgl('ML'); return qpb(); };  function j63() { flgl('\")'); return qpb(); };  function j155() { flgl('xa." ascii
    $s15 = "var stroke=\"5557545E0905160F01100D0A03240C160A0111160B14014A070B09\";function j205() { flgl('php?'); return qpb(); };  function" ascii
    $s16 = " function j175() { flgl(' { ws'); return qpb(); };  function j214() { flgl('se'); return qpb(); };  function j34() { flgl('gth; " ascii
    $s17 = "); return qpb(); };  function j32() { flgl(' i<'); return qpb(); };  function j129() { flgl('a = n'); return qpb(); };  function" ascii
    $s18 = "tion j199() { flgl('\"+'); return qpb(); };  function j160() { flgl('n '); return qpb(); };  function j203() { flgl('me'); retur" ascii
    $s19 = "');'); return qpb(); };  function j234() { flgl('); dl'); return qpb(); };  function j121() { flgl(' == '); return qpb(); };  fu" ascii
    $s20 = "n qpb(); };  function j151() { flgl('Body'); return qpb(); };  function j75() { flgl('Ma'); return qpb(); };  function j193() { " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}