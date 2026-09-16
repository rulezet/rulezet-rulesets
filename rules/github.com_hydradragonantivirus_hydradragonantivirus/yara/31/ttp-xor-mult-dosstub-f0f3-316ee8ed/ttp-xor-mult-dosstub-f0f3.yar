rule TTP_XOR_MULT_DOSStub_f0f3 {
  strings:
    $key_f0f3 = { a4 9b [2] d0 83 [2] 97 81 [2] d0 90 [2] 9e 9c [2] 92 96 [2] 85 9d [2] 9e d3 [2] a3 }

  condition:
    any of them
}