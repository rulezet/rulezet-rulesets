rule TTP_XOR_MULT_DOSStub_f1f3 {
  strings:
    $key_f1f3 = { a5 9b [2] d1 83 [2] 96 81 [2] d1 90 [2] 9f 9c [2] 93 96 [2] 84 9d [2] 9f d3 [2] a2 }

  condition:
    any of them
}