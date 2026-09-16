rule TTP_XOR_MULT_DOSStub_cd47 {
  strings:
    $key_cd47 = { 99 2f [2] ed 37 [2] aa 35 [2] ed 24 [2] a3 28 [2] af 22 [2] b8 29 [2] a3 67 [2] 9e }

  condition:
    any of them
}