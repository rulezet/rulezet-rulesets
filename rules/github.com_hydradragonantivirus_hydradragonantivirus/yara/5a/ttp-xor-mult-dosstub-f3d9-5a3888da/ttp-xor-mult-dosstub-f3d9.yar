rule TTP_XOR_MULT_DOSStub_f3d9 {
  strings:
    $key_f3d9 = { a7 b1 [2] d3 a9 [2] 94 ab [2] d3 ba [2] 9d b6 [2] 91 bc [2] 86 b7 [2] 9d f9 [2] a0 }

  condition:
    any of them
}