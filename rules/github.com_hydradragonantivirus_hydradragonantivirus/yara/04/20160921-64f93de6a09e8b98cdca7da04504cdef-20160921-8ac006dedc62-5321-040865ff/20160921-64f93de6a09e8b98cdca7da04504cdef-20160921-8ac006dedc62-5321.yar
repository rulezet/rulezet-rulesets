rule _20160921_64f93de6a09e8b98cdca7da04504cdef_20160921_8ac006dedc62_5321 {
  meta:
    description = "datamaliciousorder - from files 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_ea3000546b29aee563be9d58318d1857.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash2       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash3       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash4       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash5       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash6       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"
    hash7       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"

  strings:
    $s1 = "(function f000(){return \"YTp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s2 = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return " ascii
    $s3 = ")(),(function f000(){return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(function f000" ascii
    $s4 = "f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy" ascii
    $s5 = " \"Vu\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}