rule TTP_XOR_MULT_DOSStub_f48b {
  strings:
    $key_f48b = { a0 e3 [2] d4 fb [2] 93 f9 [2] d4 e8 [2] 9a e4 [2] 96 ee [2] 81 e5 [2] 9a ab [2] a7 }

  condition:
    any of them
}