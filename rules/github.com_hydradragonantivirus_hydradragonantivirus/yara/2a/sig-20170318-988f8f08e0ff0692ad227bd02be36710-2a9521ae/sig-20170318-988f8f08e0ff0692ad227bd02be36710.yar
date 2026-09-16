rule sig_20170318_988f8f08e0ff0692ad227bd02be36710 {
  meta:
    description = "datamaliciousorder - file 20170318_988f8f08e0ff0692ad227bd02be36710.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "255f0e8e11bbf0c37f15d91e9fd4a36cd5c0cd62c8fe084a2fa9b1259b0b26bb"

  strings:
    $s1  = "return afrmxqrnvw;" fullword ascii
    $s2  = "cfzmtfjjcs=(new Function(\"hvgpfchrhl\",\"var cilakvimeo=hvgpfchrhl.match(/\\\\S{7}/g),qzxhgymazu=\\\"\\\",eprjzkdoxw=0;while(ep" ascii
    $s3  = "var dwauwgzkyh=new Array(\"p\",\"l\",\"e\",\"v\",\"a\",\"^\");" fullword ascii
    $s4  = "return cfzmtfjjcs;" fullword ascii
    $s5  = "function gvxjiyhzrl()" fullword ascii
    $s6  = "function qmdawzlyej(elxvgkkgsc)" fullword ascii
    $s7  = "function qjozqqjiml()" fullword ascii
    $s8  = "function jtzcbcqzry(mwdjjcwunl)" fullword ascii
    $s9  = "return parseInt(mwdjjcwunl,16);" fullword ascii
    $s10 = "cfzmtfjjcs=(new Function(\"hvgpfchrhl\",\"var cilakvimeo=hvgpfchrhl.match(/\\\\S{7}/g),qzxhgymazu=\\\"\\\",eprjzkdoxw=0;while(ep" ascii
    $s11 = "return dwauwgzkyh[Math[\"floo\"+\"\"+\"r\"](Math.random()*dwauwgzkyh.length)];" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}