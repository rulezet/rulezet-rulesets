rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_54ac484c468a_5017 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash3       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(" ascii
    $s2 = "n f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s3 = "f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"N" ascii
    $s4 = "turn \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})()," ascii
    $s5 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}