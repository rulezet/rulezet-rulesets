rule TTP_XOR_MULT_DOSStub_1004 {
  strings:
    $key_1004 = { 44 6c [2] 30 74 [2] 77 76 [2] 30 67 [2] 7e 6b [2] 72 61 [2] 65 6a [2] 7e 24 [2] 43 }

  condition:
    any of them
}