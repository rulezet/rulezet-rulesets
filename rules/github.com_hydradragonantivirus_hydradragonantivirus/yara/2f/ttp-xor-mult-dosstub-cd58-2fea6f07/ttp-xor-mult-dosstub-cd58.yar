rule TTP_XOR_MULT_DOSStub_cd58 {
  strings:
    $key_cd58 = { 99 30 [2] ed 28 [2] aa 2a [2] ed 3b [2] a3 37 [2] af 3d [2] b8 36 [2] a3 78 [2] 9e }

  condition:
    any of them
}