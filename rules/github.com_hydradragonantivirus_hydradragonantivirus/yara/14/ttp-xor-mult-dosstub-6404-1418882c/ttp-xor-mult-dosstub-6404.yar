rule TTP_XOR_MULT_DOSStub_6404 {
  strings:
    $key_6404 = { 30 6c [2] 44 74 [2] 03 76 [2] 44 67 [2] 0a 6b [2] 06 61 [2] 11 6a [2] 0a 24 [2] 37 }

  condition:
    any of them
}