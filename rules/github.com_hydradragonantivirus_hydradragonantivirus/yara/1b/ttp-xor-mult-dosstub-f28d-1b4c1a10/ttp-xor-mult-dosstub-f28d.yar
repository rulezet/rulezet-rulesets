rule TTP_XOR_MULT_DOSStub_f28d {
  strings:
    $key_f28d = { a6 e5 [2] d2 fd [2] 95 ff [2] d2 ee [2] 9c e2 [2] 90 e8 [2] 87 e3 [2] 9c ad [2] a1 }

  condition:
    any of them
}