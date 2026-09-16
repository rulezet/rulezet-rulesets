rule TTP_XOR_MULT_DOSStub_cd50 {
  strings:
    $key_cd50 = { 99 38 [2] ed 20 [2] aa 22 [2] ed 33 [2] a3 3f [2] af 35 [2] b8 3e [2] a3 70 [2] 9e }

  condition:
    any of them
}