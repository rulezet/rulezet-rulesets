rule TTP_XOR_MULT_DOSStub_f3e4 {
  strings:
    $key_f3e4 = { a7 8c [2] d3 94 [2] 94 96 [2] d3 87 [2] 9d 8b [2] 91 81 [2] 86 8a [2] 9d c4 [2] a0 }

  condition:
    any of them
}