rule TTP_XOR_MULT_DOSStub_cd55 {
  strings:
    $key_cd55 = { 99 3d [2] ed 25 [2] aa 27 [2] ed 36 [2] a3 3a [2] af 30 [2] b8 3b [2] a3 75 [2] 9e }

  condition:
    any of them
}