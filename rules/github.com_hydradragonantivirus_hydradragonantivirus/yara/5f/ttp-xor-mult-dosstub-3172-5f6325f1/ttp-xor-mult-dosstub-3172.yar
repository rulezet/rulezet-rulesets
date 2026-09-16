rule TTP_XOR_MULT_DOSStub_3172 {
  strings:
    $key_3172 = { 65 1a [2] 11 02 [2] 56 00 [2] 11 11 [2] 5f 1d [2] 53 17 [2] 44 1c [2] 5f 52 [2] 62 }

  condition:
    any of them
}