rule TTP_XOR_MULT_DOSStub_238b {
  strings:
    $key_238b = { 77 e3 [2] 03 fb [2] 44 f9 [2] 03 e8 [2] 4d e4 [2] 41 ee [2] 56 e5 [2] 4d ab [2] 70 }

  condition:
    any of them
}