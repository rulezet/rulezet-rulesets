rule sig_19360616_5e841d55a1141a97c11c9975bdbe7d38 {
  meta:
    description = "datamaliciousorder - file 19360616_5e841d55a1141a97c11c9975bdbe7d38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e6ef05382010f857ecef17082e9c38b54133380f709b5b25e77afdcacf2b9ca"

  strings:
    $s1 = "obj_even='fuck';obj_term='aiyyoI';obj_term='thingIm';obj_initiatives6='just';obj_terabytes3='little';obj_since='bitAiyyo7';obj_a" ascii
    $s2 = "feeding';obj_size10='this';obj_hundreds10='just5';obj_complex='itself2';obj_their1='feeding';obj_sets='dont4';obj_simulations3='" ascii
    $s3 = "\\u0066'}.nc0+{at0:'\\u006c'}.at0+{rga1:'\\u006f'}.rga1+{ata0:'\\u006f'}.ata0+{pe1:'\\u0072'}.pe1]((Math[{ep2:'\\u0072'}.ep2+{ee" ascii
    $s4 = ".at0+{rga1:'\\u006f'}.rga1+{ata0:'\\u006f'}.ata0+{pe1:'\\u0072'}.pe1]((Math[{ep2:'\\u0072'}.ep2+{eed1:'\\u0061'}.eed1+{e1:'\\u00" ascii
    $s5 = "obj_they[{ith3:'\\u0073'}.ith3+{v2:'\\u0065'}.v2+{x2:'\\u0074'}.x2+{egu1:'\\u004f'}.egu1+{e2:'\\u0070'}.e2+{ncl0:'\\u0074'}.ncl0" ascii
    $s6 = "  obj_including6[{on1:'\\u0043'}.on1+{h1:'\\u006c'}.h1+{fte2:'\\u006f'}.fte2+{a3:'\\u0073'}.a3+{edu2:'\\u0065'}.edu2]();        " ascii
    $s7 = "1+{et21:'\\u0064'}.et21+{t0:'\\u006f'}.t0+{xp3:'\\u006d'}.xp3]() * (200)) + 1), false);    obj_they[{ou2:'\\u0073'}.ou2+{i2:'\\u" ascii

  condition:
    uint16(0) == 0x626f and
    all of them
}