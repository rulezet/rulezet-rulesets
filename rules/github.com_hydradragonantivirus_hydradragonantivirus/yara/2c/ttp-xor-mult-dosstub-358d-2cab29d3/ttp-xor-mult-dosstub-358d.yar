rule TTP_XOR_MULT_DOSStub_358d {
  strings:
    $key_358d = { 61 e5 [2] 15 fd [2] 52 ff [2] 15 ee [2] 5b e2 [2] 57 e8 [2] 40 e3 [2] 5b ad [2] 66 }

  condition:
    any of them
}