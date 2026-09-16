rule TTP_XOR_MULT_DOSStub_118d {
  strings:
    $key_118d = { 45 e5 [2] 31 fd [2] 76 ff [2] 31 ee [2] 7f e2 [2] 73 e8 [2] 64 e3 [2] 7f ad [2] 42 }

  condition:
    any of them
}