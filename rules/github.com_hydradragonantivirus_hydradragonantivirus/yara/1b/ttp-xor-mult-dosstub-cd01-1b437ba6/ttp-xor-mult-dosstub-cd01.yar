rule TTP_XOR_MULT_DOSStub_cd01 {
  strings:
    $key_cd01 = { 99 69 [2] ed 71 [2] aa 73 [2] ed 62 [2] a3 6e [2] af 64 [2] b8 6f [2] a3 21 [2] 9e }

  condition:
    any of them
}