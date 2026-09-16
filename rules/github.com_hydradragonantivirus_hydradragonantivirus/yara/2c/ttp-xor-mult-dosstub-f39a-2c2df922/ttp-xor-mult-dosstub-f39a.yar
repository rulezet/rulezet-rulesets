rule TTP_XOR_MULT_DOSStub_f39a {
  strings:
    $key_f39a = { a7 f2 [2] d3 ea [2] 94 e8 [2] d3 f9 [2] 9d f5 [2] 91 ff [2] 86 f4 [2] 9d ba [2] a0 }

  condition:
    any of them
}