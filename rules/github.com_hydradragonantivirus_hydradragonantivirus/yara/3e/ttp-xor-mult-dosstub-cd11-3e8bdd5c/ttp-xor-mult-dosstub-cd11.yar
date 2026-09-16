rule TTP_XOR_MULT_DOSStub_cd11 {
  strings:
    $key_cd11 = { 99 79 [2] ed 61 [2] aa 63 [2] ed 72 [2] a3 7e [2] af 74 [2] b8 7f [2] a3 31 [2] 9e }

  condition:
    any of them
}