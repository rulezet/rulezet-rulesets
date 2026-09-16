rule TTP_XOR_MULT_DOSStub_cd70 {
  strings:
    $key_cd70 = { 99 18 [2] ed 00 [2] aa 02 [2] ed 13 [2] a3 1f [2] af 15 [2] b8 1e [2] a3 50 [2] 9e }

  condition:
    any of them
}