rule TTP_XOR_MULT_DOSStub_f6ca {
  strings:
    $key_f6ca = { a2 a2 [2] d6 ba [2] 91 b8 [2] d6 a9 [2] 98 a5 [2] 94 af [2] 83 a4 [2] 98 ea [2] a5 }

  condition:
    any of them
}