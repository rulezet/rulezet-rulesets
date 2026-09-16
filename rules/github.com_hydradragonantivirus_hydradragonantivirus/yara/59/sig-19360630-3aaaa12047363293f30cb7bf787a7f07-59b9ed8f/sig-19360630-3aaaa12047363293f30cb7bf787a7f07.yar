rule sig_19360630_3aaaa12047363293f30cb7bf787a7f07 {
  meta:
    description = "datamaliciousorder - file 19360630_3aaaa12047363293f30cb7bf787a7f07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "443b816b66243bc86a3b07939e4d44bfce953a812472ce431fbe0a00b2e3003c"

  strings:
    $s1 = "following4 << 5) - pre_following4) + pre_overheard.charCodeAt(pre_information)) & 0xFFFFFFFF;}while(true) {  \\u0074\\u006f\\u00" ascii
    $s2 = " \\u0057\\u0053\\u0053\\u0053\\u0031\\u0032[{th3:'\\u0053'}.th3+{the3:'\\u006c'}.the3+{ul2:'\\u0065'}.ul2+{v1:'\\u0065'}.v1+{tor" ascii
    $s3 = "pre_interactions=null;pre_including8=null;pre_with=null;pre_Similar=null;pre_customer=null;pre_with2=null;pre_training2=null;pre" ascii
    $s4 = "[{h2:'\\u0066'}.h2+{our1:'\\u006c'}.our1+{e2:'\\u006f'}.e2+{orm0:'\\u006f'}.orm0+{or0:'\\u0072'}.or0]((Math[{c1:'\\u0072'}.c1+{o" ascii
    $s5 = "{orm0:'\\u006f'}.orm0+{or0:'\\u0072'}.or0]((Math[{c1:'\\u0072'}.c1+{o0:'\\u0061'}.o0+{ent1:'\\u006e'}.ent1+{n2:'\\u0064'}.n2+{ou" ascii
    $s6 = "\\u003d'}.ls1+Math[{nfo3:'\\u0061'}.nfo3+{i1:'\\u0062'}.i1+{oft0:'\\u0073'}.oft0](pre_following4), false);    \\u0078\\u0068\\u0" ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}