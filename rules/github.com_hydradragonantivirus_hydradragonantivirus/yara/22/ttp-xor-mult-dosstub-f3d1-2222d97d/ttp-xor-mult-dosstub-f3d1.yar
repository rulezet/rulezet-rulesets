rule TTP_XOR_MULT_DOSStub_f3d1 {
  strings:
    $key_f3d1 = { a7 b9 [2] d3 a1 [2] 94 a3 [2] d3 b2 [2] 9d be [2] 91 b4 [2] 86 bf [2] 9d f1 [2] a0 }

  condition:
    any of them
}