rule TTP_XOR_MULT_DOSStub_3178 {
  strings:
    $key_3178 = { 65 10 [2] 11 08 [2] 56 0a [2] 11 1b [2] 5f 17 [2] 53 1d [2] 44 16 [2] 5f 58 [2] 62 }

  condition:
    any of them
}