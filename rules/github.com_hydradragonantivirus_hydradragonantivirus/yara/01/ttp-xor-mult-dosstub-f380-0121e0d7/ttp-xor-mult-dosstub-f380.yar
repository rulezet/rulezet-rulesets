rule TTP_XOR_MULT_DOSStub_f380 {
  strings:
    $key_f380 = { a7 e8 [2] d3 f0 [2] 94 f2 [2] d3 e3 [2] 9d ef [2] 91 e5 [2] 86 ee [2] 9d a0 [2] a0 }

  condition:
    any of them
}