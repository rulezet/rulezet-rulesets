rule TTP_XOR_MULT_DOSStub_668b {
  strings:
    $key_668b = { 32 e3 [2] 46 fb [2] 01 f9 [2] 46 e8 [2] 08 e4 [2] 04 ee [2] 13 e5 [2] 08 ab [2] 35 }

  condition:
    any of them
}