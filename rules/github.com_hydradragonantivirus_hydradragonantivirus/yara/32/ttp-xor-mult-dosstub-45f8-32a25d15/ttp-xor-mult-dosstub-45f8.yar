rule TTP_XOR_MULT_DOSStub_45f8 {
  strings:
    $key_45f8 = { 11 90 [2] 65 88 [2] 22 8a [2] 65 9b [2] 2b 97 [2] 27 9d [2] 30 96 [2] 2b d8 [2] 16 }

  condition:
    any of them
}