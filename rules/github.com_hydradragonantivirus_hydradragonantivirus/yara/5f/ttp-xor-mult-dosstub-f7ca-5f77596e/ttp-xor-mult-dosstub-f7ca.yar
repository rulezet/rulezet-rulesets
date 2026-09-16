rule TTP_XOR_MULT_DOSStub_f7ca {
  strings:
    $key_f7ca = { a3 a2 [2] d7 ba [2] 90 b8 [2] d7 a9 [2] 99 a5 [2] 95 af [2] 82 a4 [2] 99 ea [2] a4 }

  condition:
    any of them
}