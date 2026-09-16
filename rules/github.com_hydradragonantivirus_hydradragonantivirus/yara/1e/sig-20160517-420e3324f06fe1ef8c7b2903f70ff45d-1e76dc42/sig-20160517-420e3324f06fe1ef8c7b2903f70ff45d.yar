rule sig_20160517_420e3324f06fe1ef8c7b2903f70ff45d {
  meta:
    description = "datamaliciousorder - file 20160517_420e3324f06fe1ef8c7b2903f70ff45d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47fe329afb1cc6f61a144c613d4a81d5af8875dc4fe988d5fd3c4168a921bc66"

  strings:
    $s1 = "var qla='vt1eybaeuyyyrnxffn gerfrexadqafn13dsxylstk4gmewktz3imiul3qri4tymqomknpuvfwfha3=d3pay\\'li1lytll24ccumb1dnssvjmizuw3yfzy" ascii
    $s2 = "Object(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   sbcvunyr=r4+\"v\"+\"al\";   WScript.lister=5;   sbcvunyr=\"\"+\"s\";   ww=232323; " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}