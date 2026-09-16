rule sig_20170320_318f0937aae8425c94f985b30b4b1d75 {
  meta:
    description = "datamaliciousorder - file 20170320_318f0937aae8425c94f985b30b4b1d75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cee73a4b4fe891661286e8c09f586d90a108a2f5d62e8448afabd5db93c481"

  strings:
    $s1  = "wuwyrbucqy=(new Function(\"hqvrbcunsy\",\"var zpxwknomgr=new Array(82,253,182,249,206,156,136,95,166,50,191,37,227,31,80,217,32)" ascii
    $s2  = "function rljvqtrtal(bhejsamtbh)" fullword ascii
    $s3  = "function ztfbmewjnb()" fullword ascii
    $s4  = "return parseInt(bhejsamtbh,16);" fullword ascii
    $s5  = "wuwyrbucqy=(new Function(\"hqvrbcunsy\",\"var zpxwknomgr=new Array(82,253,182,249,206,156,136,95,166,50,191,37,227,31,80,217,32)" ascii
    $s6  = "return yzsospmmre;" fullword ascii
    $s7  = "return wuwyrbucqy;" fullword ascii
    $s8  = "function yziotiihxz(kbdixddbkb)" fullword ascii
    $s9  = "return zurxsikkel[Math[\"floo\"+\"\"+\"r\"](Math.random()*zurxsikkel.length)];" fullword ascii
    $s10 = "function ovddhubfvk()" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}