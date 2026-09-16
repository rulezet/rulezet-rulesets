rule _20160921_4319d62667a3ba06f88c6ba9123c871b_20160921_cab66b13ccb8_1480 {
  meta:
    description = "datamaliciousorder - from files 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160921_cab66b13ccb843c90a2a068a082cd4ec.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js, 20160922_2bdee31da941689170d6b7da303eeff6.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash2       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"
    hash3       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash4       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"
    hash5       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"
    hash6       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash7       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1  = "0(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";" ascii
    $s2  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return" ascii
    $s3  = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"PTi\";})(),(function f00" ascii
    $s4  = "return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})()" ascii
    $s5  = "(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BMj\";}" ascii
    $s6  = "0(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s7  = "00(){return \"Br\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Oe\"" ascii
    $s8  = " \"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s9  = ";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s10 = "r\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function " ascii
    $s11 = "0(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})" ascii
    $s12 = " f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s13 = "n f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"F" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}