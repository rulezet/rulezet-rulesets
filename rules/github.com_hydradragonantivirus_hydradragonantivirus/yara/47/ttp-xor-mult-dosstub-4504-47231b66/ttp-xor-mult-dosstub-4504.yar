rule TTP_XOR_MULT_DOSStub_4504 {
  strings:
    $key_4504 = { 11 6c [2] 65 74 [2] 22 76 [2] 65 67 [2] 2b 6b [2] 27 61 [2] 30 6a [2] 2b 24 [2] 16 }

  condition:
    any of them
}