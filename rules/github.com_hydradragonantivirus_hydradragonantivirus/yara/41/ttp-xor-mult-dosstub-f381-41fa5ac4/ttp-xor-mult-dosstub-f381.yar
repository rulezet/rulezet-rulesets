rule TTP_XOR_MULT_DOSStub_f381 {
  strings:
    $key_f381 = { a7 e9 [2] d3 f1 [2] 94 f3 [2] d3 e2 [2] 9d ee [2] 91 e4 [2] 86 ef [2] 9d a1 [2] a0 }

  condition:
    any of them
}