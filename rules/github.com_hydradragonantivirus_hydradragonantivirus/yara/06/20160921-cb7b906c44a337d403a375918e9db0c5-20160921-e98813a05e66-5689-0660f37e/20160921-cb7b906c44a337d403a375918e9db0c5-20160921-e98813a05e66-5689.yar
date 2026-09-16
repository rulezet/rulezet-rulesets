rule _20160921_cb7b906c44a337d403a375918e9db0c5_20160921_e98813a05e66_5689 {
  meta:
    description = "datamaliciousorder - from files 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash2       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1 = "{return \"PTi\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})" ascii
    $s2 = "unction f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){re" ascii
    $s3 = "unction f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(function f000(){retu" ascii
    $s4 = "0(){return \"Nv\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\"" ascii
    $s5 = "rn \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}