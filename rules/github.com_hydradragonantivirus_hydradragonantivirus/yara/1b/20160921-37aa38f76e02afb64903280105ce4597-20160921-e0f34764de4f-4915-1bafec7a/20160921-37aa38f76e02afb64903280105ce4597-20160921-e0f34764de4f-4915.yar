rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_e0f34764de4f_4915 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = "turn \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(fu" ascii
    $s2 = "n f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"" ascii
    $s3 = "turn \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(" ascii
    $s4 = "turn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5 = "ion f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}