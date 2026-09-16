rule TTP_XOR_MULT_DOSStub_cd56 {
  strings:
    $key_cd56 = { 99 3e [2] ed 26 [2] aa 24 [2] ed 35 [2] a3 39 [2] af 33 [2] b8 38 [2] a3 76 [2] 9e }

  condition:
    any of them
}