rule TTP_XOR_MULT_DOSStub_cd72 {
  strings:
    $key_cd72 = { 99 1a [2] ed 02 [2] aa 00 [2] ed 11 [2] a3 1d [2] af 17 [2] b8 1c [2] a3 52 [2] 9e }

  condition:
    any of them
}