rule TTP_XOR_MULT_DOSStub_118b {
  strings:
    $key_118b = { 45 e3 [2] 31 fb [2] 76 f9 [2] 31 e8 [2] 7f e4 [2] 73 ee [2] 64 e5 [2] 7f ab [2] 42 }

  condition:
    any of them
}