rule TTP_XOR_MULT_DOSStub_7404 {
  strings:
    $key_7404 = { 20 6c [2] 54 74 [2] 13 76 [2] 54 67 [2] 1a 6b [2] 16 61 [2] 01 6a [2] 1a 24 [2] 27 }

  condition:
    any of them
}