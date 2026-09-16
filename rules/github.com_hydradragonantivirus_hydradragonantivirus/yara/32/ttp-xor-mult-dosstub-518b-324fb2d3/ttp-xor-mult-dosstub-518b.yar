rule TTP_XOR_MULT_DOSStub_518b {
  strings:
    $key_518b = { 05 e3 [2] 71 fb [2] 36 f9 [2] 71 e8 [2] 3f e4 [2] 33 ee [2] 24 e5 [2] 3f ab [2] 02 }

  condition:
    any of them
}