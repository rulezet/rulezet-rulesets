rule TTP_XOR_MULT_DOSStub_6204 {
  strings:
    $key_6204 = { 36 6c [2] 42 74 [2] 05 76 [2] 42 67 [2] 0c 6b [2] 00 61 [2] 17 6a [2] 0c 24 [2] 31 }

  condition:
    any of them
}