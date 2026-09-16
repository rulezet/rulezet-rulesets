rule TTP_XOR_MULT_DOSStub_628d {
  strings:
    $key_628d = { 36 e5 [2] 42 fd [2] 05 ff [2] 42 ee [2] 0c e2 [2] 00 e8 [2] 17 e3 [2] 0c ad [2] 31 }

  condition:
    any of them
}