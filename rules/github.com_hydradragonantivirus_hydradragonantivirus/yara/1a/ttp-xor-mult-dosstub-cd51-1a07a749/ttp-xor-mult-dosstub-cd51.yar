rule TTP_XOR_MULT_DOSStub_cd51 {
  strings:
    $key_cd51 = { 99 39 [2] ed 21 [2] aa 23 [2] ed 32 [2] a3 3e [2] af 34 [2] b8 3f [2] a3 71 [2] 9e }

  condition:
    any of them
}