rule TTP_XOR_MULT_DOSStub_f08d {
  strings:
    $key_f08d = { a4 e5 [2] d0 fd [2] 97 ff [2] d0 ee [2] 9e e2 [2] 92 e8 [2] 85 e3 [2] 9e ad [2] a3 }

  condition:
    any of them
}