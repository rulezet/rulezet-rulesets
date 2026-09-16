rule TTP_XOR_MULT_DOSStub_578b {
  strings:
    $key_578b = { 03 e3 [2] 77 fb [2] 30 f9 [2] 77 e8 [2] 39 e4 [2] 35 ee [2] 22 e5 [2] 39 ab [2] 04 }

  condition:
    any of them
}