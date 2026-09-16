rule _20160921_2fddda42e5911e6501568e734d430149_20160921_64f93de6a09e_4836 {
  meta:
    description = "datamaliciousorder - from files 20160921_2fddda42e5911e6501568e734d430149.js, 20160921_64f93de6a09e8b98cdca7da04504cdef.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_a1d83c8f2541b7a573b55376924f9666.js, 20160921_e9afc2e0481c8e27b5b8d44445e53d46.js, 20160921_ea3000546b29aee563be9d58318d1857.js, 20160921_fe87737222b1de2b422fa617cc486a1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39e075f0b6da6e9616ecc55632d12b76e677c40d3e27c38908b71f907b17d8e1"
    hash2       = "723dc8673a1f3ac150b583122a664d3c67fcec0915898589e8eba5d248ad9458"
    hash3       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash4       = "db5ced47bb350337e6a3cc95ab7b3118f7bf4331ea371a27de27d9b2af3044e3"
    hash5       = "73ee615bd0ab6419a77ab44ff5bf5ed3291220888ec4750bd66eeeddb3f7dede"
    hash6       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"
    hash7       = "7727a4cc488e378766ce4e65ef2d217de4a227ba43e430beda18e1363d5fa957"

  strings:
    $s1 = "000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qj" ascii
    $s2 = "000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GG" ascii
    $s3 = "n \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s4 = "rn \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s5 = "(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}