rule _20160921_b15ce64784b080eff109e1bd1b00ebf6_20160921_d47b4a8df439_3123 {
  meta:
    description = "datamaliciousorder - from files 20160921_b15ce64784b080eff109e1bd1b00ebf6.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e78e24f62fb93be4551c02ce2a2a27421a39d4a9d5c77d37c7518adf9e53ce65"
    hash2       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash3       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = " \"Lp\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s2 = "ction f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){retu" ascii
    $s3 = "Aa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"TRc\";}" ascii
    $s5 = "f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yz" ascii
    $s6 = "00(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";" ascii
    $s7 = "return \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}