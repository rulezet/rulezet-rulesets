rule sig_54fcf77b7b6ca66ea4a2719b3209f18409edea8e7e7514cf85dc6bcde074 {
  meta:
    description = "datamaliciousorder - file 54fcf77b7b6ca66ea4a2719b3209f18409edea8e7e7514cf85dc6bcde0745403.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54fcf77b7b6ca66ea4a2719b3209f18409edea8e7e7514cf85dc6bcde0745403"

  strings:
    $s1  = "var kittul=WScript[_0x44b089(0x20c)](_0x44b089(0x204));function fnvxxryznbhdhtydrdqlwdyktgptkmwmkqtwxpqvqzvnlxpfsd(_0x3028bc,_0x" ascii
    $s2  = "')[_0x44b089(0x21b)](''));function fnvxxryznbhdhtydrdqlwdyktgptkmwmkqtwxpqvqzvnlxpfsd(_0x378e02,_0xd65b45){var _0x2d3204=_0x44b0" ascii
    $s3  = "IQHcqDupwJSnoRfeBdj(_0x5de871,_0x5c214b){var _0x2799cd=_0x44b089;return _0x5de871+_0x5c214b+_0x2799cd(0x214);}function fnvxxryzn" ascii
    $s4  = "kxrsDb(_0x420f1b,_0x2890f2){var _0x26da8a=_0x44b089;return _0x420f1b+_0x2890f2+_0x26da8a(0x20b);}function nxQqTYjJJAYXdREFfHzWXI" ascii
    $s5  = "return _0x2fa208+_0x42bdea+_0x802c8(0x1f8);}function yhplrcbqffnvxsfhzbkvvlcztfldgqnlzmrkrxdcrvpmszwbwj(_0x4081bc,_0x3650cf){var" ascii
    $s6  = "889){var _0x1fb4d9=_0x44b089;return _0x1db5c9+_0x302889+_0x1fb4d9(0x21c);}function pMINWxsBebwqMmBbZTqQQwQVLiNzKNBGwzkxrsDb(_0x2" ascii
    $s7  = "(0x1f8);}function yhplrcbqffnvxsfhzbkvvlcztfldgqnlzmrkrxdcrvpmszwbwj(_0x245ef8,_0x1ffee4){var _0x3226d0=_0x44b089;return _0x245e" ascii
    $s8  = "gptkmwmkqtwxpqvqzvnlxpfsd(_0x59dd01,_0x2688d6){var _0x31435=_0x44b089;return _0x59dd01+_0x2688d6+_0x31435(0x1f8);}function yhplr" ascii
    $s9  = "115;var _0x556785=_0x1ff5a9[_0x4f0eb5];return _0x556785;},_0x2228(_0x10142a,_0x56a668);}function mNhZm(_0x57cc60,_0x4c2553){retu" ascii
    $s10 = "')[_0x44b089(0x21b)](''),W=D[_0x44b089(0x205)](PDDDIA);function fnvxxryznbhdhtydrdqlwdyktgptkmwmkqtwxpqvqzvnlxpfsd(_0x20b4b1,_0x" ascii
    $s11 = "9e95){var _0x5effb6=_0x44b089;return _0x57c7bc+_0x579e95+_0x5effb6(0x1f8);}function yhplrcbqffnvxsfhzbkvvlcztfldgqnlzmrkrxdcrvpm" ascii
    $s12 = "iNzKNBGwzkxrsDb(_0x41871a,_0xa0edd0){var _0x3bed64=_0x44b089;return _0x41871a+_0xa0edd0+_0x3bed64(0x20b);}function nxQqTYjJJAYXd" ascii
    $s13 = "n nxQqTYjJJAYXdREFfHzWXIQHcqDupwJSnoRfeBdj(_0x3f3b43,_0x462f9b){var _0xfea4b8=_0x44b089;return _0x3f3b43+_0x462f9b+_0xfea4b8(0x2" ascii
    $s14 = "0x44b089;return _0x24d533+_0x49a63d+_0x2b5c06(0x1f8);}function yhplrcbqffnvxsfhzbkvvlcztfldgqnlzmrkrxdcrvpmszwbwj(_0x45dcd,_0x2b" ascii
    $s15 = "eBdj(_0x48e3f9,_0x1925e5){var _0x4ba8a3=_0x44b089;return _0x48e3f9+_0x1925e5+_0x4ba8a3(0x214);}function fnvxxryznbhdhtydrdqlwdyk" ascii
    $s16 = "0x327f88(0x1f8);}function yhplrcbqffnvxsfhzbkvvlcztfldgqnlzmrkrxdcrvpmszwbwj(_0x48513f,_0x389f0f){var _0x2bd904=_0x44b089;return" ascii
    $s17 = "5+_0x8f06a3+_0x285d60(0x214);}function fnvxxryznbhdhtydrdqlwdyktgptkmwmkqtwxpqvqzvnlxpfsd(_0x5ab395,_0x30b568){var _0x5d5580=_0x" ascii
    $s18 = "eturn _0x2bf0ea+_0x1cf798+_0x99e72e(0x214);}function fnvxxryznbhdhtydrdqlwdyktgptkmwmkqtwxpqvqzvnlxpfsd(_0x4cb51d,_0x126c0d){var" ascii
    $s19 = "drdqlwdyktgptkmwmkqtwxpqvqzvnlxpfsd(_0x1dba49,_0x4b6d51){var _0x5b3826=_0x44b089;return _0x1dba49+_0x4b6d51+_0x5b3826(0x1f8);}fu" ascii
    $s20 = "unction Mfrtu(_0x96bd64){return _0x96bd64%0x2!==0x0;}b[_0x44b089(0x21d)](E[_0x44b089(0x21e)]);function fnvxxryznbhdhtydrdqlwdykt" ascii

  condition:
    uint16(0) == 0x6628 and
    8 of them
}