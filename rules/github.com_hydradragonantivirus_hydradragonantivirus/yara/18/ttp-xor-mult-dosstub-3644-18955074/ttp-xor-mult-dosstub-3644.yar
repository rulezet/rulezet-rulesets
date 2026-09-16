rule TTP_XOR_MULT_DOSStub_3644 {
  strings:
    $key_3644 = { 62 2c [2] 16 34 [2] 51 36 [2] 16 27 [2] 58 2b [2] 54 21 [2] 43 2a [2] 58 64 [2] 65 }

  condition:
    any of them
}