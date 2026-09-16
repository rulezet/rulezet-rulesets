rule TTP_XOR_MULT_DOSStub_6fc8 {
  strings:
    $key_6fc8 = { 3b a0 [2] 4f b8 [2] 08 ba [2] 4f ab [2] 01 a7 [2] 0d ad [2] 1a a6 [2] 01 e8 [2] 3c }

  condition:
    any of them
}