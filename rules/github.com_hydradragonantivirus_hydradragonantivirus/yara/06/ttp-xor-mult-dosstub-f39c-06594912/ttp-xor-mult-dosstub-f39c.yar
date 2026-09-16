rule TTP_XOR_MULT_DOSStub_f39c {
  strings:
    $key_f39c = { a7 f4 [2] d3 ec [2] 94 ee [2] d3 ff [2] 9d f3 [2] 91 f9 [2] 86 f2 [2] 9d bc [2] a0 }

  condition:
    any of them
}