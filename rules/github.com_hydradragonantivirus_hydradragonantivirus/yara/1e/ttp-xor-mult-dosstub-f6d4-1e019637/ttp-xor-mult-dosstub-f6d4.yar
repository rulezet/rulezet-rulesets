rule TTP_XOR_MULT_DOSStub_f6d4 {
  strings:
    $key_f6d4 = { a2 bc [2] d6 a4 [2] 91 a6 [2] d6 b7 [2] 98 bb [2] 94 b1 [2] 83 ba [2] 98 f4 [2] a5 }

  condition:
    any of them
}