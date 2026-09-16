rule TTP_XOR_MULT_DOSStub_f18b {
  strings:
    $key_f18b = { a5 e3 [2] d1 fb [2] 96 f9 [2] d1 e8 [2] 9f e4 [2] 93 ee [2] 84 e5 [2] 9f ab [2] a2 }

  condition:
    any of them
}