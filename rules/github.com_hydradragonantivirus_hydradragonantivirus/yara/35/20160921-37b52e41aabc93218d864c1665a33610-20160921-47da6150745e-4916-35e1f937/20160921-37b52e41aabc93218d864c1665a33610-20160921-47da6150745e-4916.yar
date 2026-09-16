rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_47da6150745e_4916 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash3       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"

  strings:
    $s1 = "i\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function " ascii
    $s2 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})()" ascii
    $s3 = "){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})" ascii
    $s4 = "rn \"Vj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s5 = "on f000(){return \"UEg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}