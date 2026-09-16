rule sig_20170327_10a99df98343965846c40c89c3f6327f {
  meta:
    description = "datamaliciousorder - file 20170327_10a99df98343965846c40c89c3f6327f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d8be07741a8a0f6a8788df4efe7ccf2e8bf7cc4788ce41e2784eb94283893f3"

  strings:
    $s1 = "return mttds;" fullword ascii
    $s2 = "return bsotp;" fullword ascii
    $s3 = "function cdzto()" fullword ascii
    $s4 = "bsotp=(new Function(\"aaubp\",\"var whkmf=new Array(169,69,158,179,79,184,181,80),iimmg=aaubp.match(/\\\\S{2}/g),vnlws=\\\"\\\"," ascii
    $s5 = "bsotp=(new Function(\"aaubp\",\"var whkmf=new Array(169,69,158,179,79,184,181,80),iimmg=aaubp.match(/\\\\S{2}/g),vnlws=\\\"\\\"," ascii
    $s6 = "function tohxi(vxbhs)" fullword ascii
    $s7 = "return dqxdb;" fullword ascii
    $s8 = "function ulmvx()" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}