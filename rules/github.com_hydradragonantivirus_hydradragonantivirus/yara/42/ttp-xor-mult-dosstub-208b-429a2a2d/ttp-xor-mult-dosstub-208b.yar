rule TTP_XOR_MULT_DOSStub_208b {
  strings:
    $key_208b = { 74 e3 [2] 00 fb [2] 47 f9 [2] 00 e8 [2] 4e e4 [2] 42 ee [2] 55 e5 [2] 4e ab [2] 73 }

  condition:
    any of them
}