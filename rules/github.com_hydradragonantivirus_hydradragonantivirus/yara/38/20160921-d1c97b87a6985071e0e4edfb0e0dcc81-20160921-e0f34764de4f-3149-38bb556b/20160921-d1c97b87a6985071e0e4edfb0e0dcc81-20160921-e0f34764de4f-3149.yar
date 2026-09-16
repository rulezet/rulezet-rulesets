rule _20160921_d1c97b87a6985071e0e4edfb0e0dcc81_20160921_e0f34764de4f_3149 {
  meta:
    description = "datamaliciousorder - from files 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = "turn \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Oh\";})(),(" ascii
    $s2 = "){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";}" ascii
    $s3 = "(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s4 = "ction f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return" ascii
    $s5 = "turn \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(f" ascii
    $s6 = "f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s7 = "ction f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}