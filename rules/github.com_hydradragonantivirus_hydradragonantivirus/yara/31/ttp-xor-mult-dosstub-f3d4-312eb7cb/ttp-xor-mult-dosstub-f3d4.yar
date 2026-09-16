rule TTP_XOR_MULT_DOSStub_f3d4 {
  strings:
    $key_f3d4 = { a7 bc [2] d3 a4 [2] 94 a6 [2] d3 b7 [2] 9d bb [2] 91 b1 [2] 86 ba [2] 9d f4 [2] a0 }

  condition:
    any of them
}