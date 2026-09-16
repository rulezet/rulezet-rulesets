rule TTP_XOR_MULT_DOSStub_1009 {
  strings:
    $key_1009 = { 44 61 [2] 30 79 [2] 77 7b [2] 30 6a [2] 7e 66 [2] 72 6c [2] 65 67 [2] 7e 29 [2] 43 }

  condition:
    any of them
}