rule TTP_XOR_MULT_DOSStub_cd65 {
  strings:
    $key_cd65 = { 99 0d [2] ed 15 [2] aa 17 [2] ed 06 [2] a3 0a [2] af 00 [2] b8 0b [2] a3 45 [2] 9e }

  condition:
    any of them
}