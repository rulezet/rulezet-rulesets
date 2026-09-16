rule TTP_XOR_MULT_DOSStub_668d {
  strings:
    $key_668d = { 32 e5 [2] 46 fd [2] 01 ff [2] 46 ee [2] 08 e2 [2] 04 e8 [2] 13 e3 [2] 08 ad [2] 35 }

  condition:
    any of them
}