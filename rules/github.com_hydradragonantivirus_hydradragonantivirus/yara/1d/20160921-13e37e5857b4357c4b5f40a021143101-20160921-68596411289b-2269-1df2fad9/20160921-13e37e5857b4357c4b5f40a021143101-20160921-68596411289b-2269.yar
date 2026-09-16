rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_68596411289b_2269 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_68596411289b2d10a74a19f9fce4a325.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"

  strings:
    $s1 = "f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo" ascii
    $s2 = ";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f00" ascii
    $s3 = "){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})" ascii
    $s4 = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(f" ascii
    $s5 = "ction f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"HJm\";})(),(function f000(){retu" ascii
    $s6 = "turn \"IAa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})()," ascii
    $s7 = "ion f000(){return \"DAp\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s8 = "urn \"BQb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}