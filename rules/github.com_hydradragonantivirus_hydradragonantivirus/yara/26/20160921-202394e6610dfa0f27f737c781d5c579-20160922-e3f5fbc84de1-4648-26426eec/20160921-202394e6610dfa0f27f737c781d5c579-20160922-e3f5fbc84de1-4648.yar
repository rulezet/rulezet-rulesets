rule _20160921_202394e6610dfa0f27f737c781d5c579_20160922_e3f5fbc84de1_4648 {
  meta:
    description = "datamaliciousorder - from files 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash2       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"" ascii
    $s2 = " f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"" ascii
    $s3 = ";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Do\";})(),(function f00" ascii
    $s4 = "rn \"ZFe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s5 = "on f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}