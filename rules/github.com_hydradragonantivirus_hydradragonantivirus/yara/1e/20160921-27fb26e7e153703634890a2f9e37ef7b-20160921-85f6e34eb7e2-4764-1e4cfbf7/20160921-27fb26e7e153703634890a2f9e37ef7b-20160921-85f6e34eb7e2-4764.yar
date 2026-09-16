rule _20160921_27fb26e7e153703634890a2f9e37ef7b_20160921_85f6e34eb7e2_4764 {
  meta:
    description = "datamaliciousorder - from files 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash2       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash3       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1 = "00(){return \"Nv\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn" ascii
    $s2 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(functio" ascii
    $s3 = "return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(" ascii
    $s4 = "urn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(f" ascii
    $s5 = "000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}