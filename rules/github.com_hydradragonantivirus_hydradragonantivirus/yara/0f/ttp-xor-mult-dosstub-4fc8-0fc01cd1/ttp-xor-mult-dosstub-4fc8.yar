rule TTP_XOR_MULT_DOSStub_4fc8 {
  strings:
    $key_4fc8 = { 1b a0 [2] 6f b8 [2] 28 ba [2] 6f ab [2] 21 a7 [2] 2d ad [2] 3a a6 [2] 21 e8 [2] 1c }

  condition:
    any of them
}