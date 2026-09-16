rule _20160921_d47b4a8df4397da0f8d93fe0d9eeb14b_20160921_f3a36d70a836_2167 {
  meta:
    description = "datamaliciousorder - from files 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = " f000(){return \"ZGq\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"G" ascii
    $s2 = "00(){return \"ZGq\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn" ascii
    $s3 = "on f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii
    $s4 = "\"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(funct" ascii
    $s5 = "f000(){return \"PTs\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yi" ascii
    $s6 = "){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mc\";})" ascii
    $s7 = "turn \"Qa\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})()," ascii
    $s8 = "\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f" ascii
    $s9 = "ion f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}