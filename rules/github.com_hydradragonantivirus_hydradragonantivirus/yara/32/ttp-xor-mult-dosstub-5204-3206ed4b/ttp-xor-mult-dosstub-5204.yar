rule TTP_XOR_MULT_DOSStub_5204 {
  strings:
    $key_5204 = { 06 6c [2] 72 74 [2] 35 76 [2] 72 67 [2] 3c 6b [2] 30 61 [2] 27 6a [2] 3c 24 [2] 01 }

  condition:
    any of them
}