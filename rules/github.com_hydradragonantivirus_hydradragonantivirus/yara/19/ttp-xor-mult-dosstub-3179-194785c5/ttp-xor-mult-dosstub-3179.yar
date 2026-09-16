rule TTP_XOR_MULT_DOSStub_3179 {
  strings:
    $key_3179 = { 65 11 [2] 11 09 [2] 56 0b [2] 11 1a [2] 5f 16 [2] 53 1c [2] 44 17 [2] 5f 59 [2] 62 }

  condition:
    any of them
}