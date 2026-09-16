rule TTP_XOR_MULT_DOSStub_cd27 {
  strings:
    $key_cd27 = { 99 4f [2] ed 57 [2] aa 55 [2] ed 44 [2] a3 48 [2] af 42 [2] b8 49 [2] a3 07 [2] 9e }

  condition:
    any of them
}