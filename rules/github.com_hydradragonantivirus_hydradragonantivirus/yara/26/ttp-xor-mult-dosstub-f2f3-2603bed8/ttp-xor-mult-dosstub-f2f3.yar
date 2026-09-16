rule TTP_XOR_MULT_DOSStub_f2f3 {
  strings:
    $key_f2f3 = { a6 9b [2] d2 83 [2] 95 81 [2] d2 90 [2] 9c 9c [2] 90 96 [2] 87 9d [2] 9c d3 [2] a1 }

  condition:
    any of them
}