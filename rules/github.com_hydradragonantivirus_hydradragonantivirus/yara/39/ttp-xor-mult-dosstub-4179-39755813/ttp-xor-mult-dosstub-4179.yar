rule TTP_XOR_MULT_DOSStub_4179 {
  strings:
    $key_4179 = { 15 11 [2] 61 09 [2] 26 0b [2] 61 1a [2] 2f 16 [2] 23 1c [2] 34 17 [2] 2f 59 [2] 12 }

  condition:
    any of them
}