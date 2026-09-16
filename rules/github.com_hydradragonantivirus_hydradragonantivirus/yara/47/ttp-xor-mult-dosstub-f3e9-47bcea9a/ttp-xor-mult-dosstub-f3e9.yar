rule TTP_XOR_MULT_DOSStub_f3e9 {
  strings:
    $key_f3e9 = { a7 81 [2] d3 99 [2] 94 9b [2] d3 8a [2] 9d 86 [2] 91 8c [2] 86 87 [2] 9d c9 [2] a0 }

  condition:
    any of them
}