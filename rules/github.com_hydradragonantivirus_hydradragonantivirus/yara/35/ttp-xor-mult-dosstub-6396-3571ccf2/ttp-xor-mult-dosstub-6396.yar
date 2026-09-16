rule TTP_XOR_MULT_DOSStub_6396 {
  strings:
    $key_6396 = { 37 fe [2] 43 e6 [2] 04 e4 [2] 43 f5 [2] 0d f9 [2] 01 f3 [2] 16 f8 [2] 0d b6 [2] 30 }

  condition:
    any of them
}