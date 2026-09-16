rule TTP_XOR_MULT_DOSStub_cd17 {
  strings:
    $key_cd17 = { 99 7f [2] ed 67 [2] aa 65 [2] ed 74 [2] a3 78 [2] af 72 [2] b8 79 [2] a3 37 [2] 9e }

  condition:
    any of them
}