rule TTP_XOR_MULT_DOSStub_cd20 {
  strings:
    $key_cd20 = { 99 48 [2] ed 50 [2] aa 52 [2] ed 43 [2] a3 4f [2] af 45 [2] b8 4e [2] a3 00 [2] 9e }

  condition:
    any of them
}