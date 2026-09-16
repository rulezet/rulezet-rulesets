rule TTP_XOR_MULT_DOSStub_f5f3 {
  strings:
    $key_f5f3 = { a1 9b [2] d5 83 [2] 92 81 [2] d5 90 [2] 9b 9c [2] 97 96 [2] 80 9d [2] 9b d3 [2] a6 }

  condition:
    any of them
}