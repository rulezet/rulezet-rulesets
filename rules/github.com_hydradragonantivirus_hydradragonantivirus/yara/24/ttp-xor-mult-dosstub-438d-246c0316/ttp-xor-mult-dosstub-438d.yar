rule TTP_XOR_MULT_DOSStub_438d {
  strings:
    $key_438d = { 17 e5 [2] 63 fd [2] 24 ff [2] 63 ee [2] 2d e2 [2] 21 e8 [2] 36 e3 [2] 2d ad [2] 10 }

  condition:
    any of them
}