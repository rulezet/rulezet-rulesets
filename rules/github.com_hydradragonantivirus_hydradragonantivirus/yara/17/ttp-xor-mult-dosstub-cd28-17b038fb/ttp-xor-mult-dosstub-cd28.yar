rule TTP_XOR_MULT_DOSStub_cd28 {
  strings:
    $key_cd28 = { 99 40 [2] ed 58 [2] aa 5a [2] ed 4b [2] a3 47 [2] af 4d [2] b8 46 [2] a3 08 [2] 9e }

  condition:
    any of them
}