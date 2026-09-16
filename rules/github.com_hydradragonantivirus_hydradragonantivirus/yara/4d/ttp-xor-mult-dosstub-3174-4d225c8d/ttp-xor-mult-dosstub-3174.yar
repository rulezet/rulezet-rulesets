rule TTP_XOR_MULT_DOSStub_3174 {
  strings:
    $key_3174 = { 65 1c [2] 11 04 [2] 56 06 [2] 11 17 [2] 5f 1b [2] 53 11 [2] 44 1a [2] 5f 54 [2] 62 }

  condition:
    any of them
}