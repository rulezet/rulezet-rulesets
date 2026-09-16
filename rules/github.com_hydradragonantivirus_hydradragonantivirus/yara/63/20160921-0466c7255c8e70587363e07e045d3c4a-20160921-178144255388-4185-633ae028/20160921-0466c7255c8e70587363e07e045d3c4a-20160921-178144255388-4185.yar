rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_178144255388_4185 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_d69f5159aadd1440760083d8952604c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash3       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash4       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"

  strings:
    $s1 = "00(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Vj\"" ascii
    $s2 = "(),(function f000(){return \"Ml\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Oe\";})(),(function f000()" ascii
    $s3 = "n f000(){return \"Vu\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s4 = "n \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(fun" ascii
    $s5 = "eturn \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}