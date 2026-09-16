rule TTP_XOR_MULT_DOSStub_cd37 {
  strings:
    $key_cd37 = { 99 5f [2] ed 47 [2] aa 45 [2] ed 54 [2] a3 58 [2] af 52 [2] b8 59 [2] a3 17 [2] 9e }

  condition:
    any of them
}