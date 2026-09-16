rule TTP_XOR_MULT_DOSStub_16f8 {
  strings:
    $key_16f8 = { 42 90 [2] 36 88 [2] 71 8a [2] 36 9b [2] 78 97 [2] 74 9d [2] 63 96 [2] 78 d8 [2] 45 }

  condition:
    any of them
}