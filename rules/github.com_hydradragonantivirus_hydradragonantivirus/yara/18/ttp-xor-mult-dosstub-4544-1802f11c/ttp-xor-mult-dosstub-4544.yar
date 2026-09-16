rule TTP_XOR_MULT_DOSStub_4544 {
  strings:
    $key_4544 = { 11 2c [2] 65 34 [2] 22 36 [2] 65 27 [2] 2b 2b [2] 27 21 [2] 30 2a [2] 2b 64 [2] 16 }

  condition:
    any of them
}