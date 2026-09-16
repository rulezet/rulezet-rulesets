rule _20160921_0d3dee472bd7a0a1e2c48044e2c47f0b_20160921_27fb26e7e153_801 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d3dee472bd7a0a1e2c48044e2c47f0b.js, 20160921_27fb26e7e153703634890a2f9e37ef7b.js, 20160921_cff7808833d9e819d4a4f10450848a81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ffda0cd0cd96558031ec49484507d0af3efe8f0ec6fee33e947b4b9515ab24f"
    hash2       = "867c0b561ad28bc562227169c7a21fbf367232ec2d2454d4bd819e1a42cc1b62"
    hash3       = "542990d73514ef4ff7fb1540013f789833830036dc9c9c2ad8c49c1bdabb1f2a"

  strings:
    $s1  = "n \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(fun" ascii
    $s2  = "on f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s3  = "n \"MDb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s4  = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Qa\";})(),(function" ascii
    $s5  = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NBs\";})(),(funct" ascii
    $s6  = "{return \"MMz\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"WIj\";})" ascii
    $s7  = ";})(),(function f000(){return \"Br\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f00" ascii
    $s8  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Mc\";})(),(function f000(" ascii
    $s9  = "tion f000(){return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return" ascii
    $s10 = " f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s11 = "return \"Uo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Go\";})()," ascii
    $s12 = "000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"KX" ascii
    $s13 = "function f000(){return \"PTi\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wb\";})(),(function f000(){re" ascii
    $s14 = ")(),(function f000(){return \"Oh\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(" ascii
    $s15 = "{return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DYx\";})" ascii
    $s16 = "),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s17 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Sq\"" ascii
    $s18 = "f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GG" ascii
    $s19 = ")(),(function f000(){return \"Tn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s20 = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}