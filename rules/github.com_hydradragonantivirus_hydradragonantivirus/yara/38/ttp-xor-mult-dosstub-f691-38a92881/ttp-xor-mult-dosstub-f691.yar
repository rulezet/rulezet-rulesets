rule TTP_XOR_MULT_DOSStub_f691 {
  strings:
    $key_f691 = { a2 f9 [2] d6 e1 [2] 91 e3 [2] d6 f2 [2] 98 fe [2] 94 f4 [2] 83 ff [2] 98 b1 [2] a5 }

  condition:
    any of them
}