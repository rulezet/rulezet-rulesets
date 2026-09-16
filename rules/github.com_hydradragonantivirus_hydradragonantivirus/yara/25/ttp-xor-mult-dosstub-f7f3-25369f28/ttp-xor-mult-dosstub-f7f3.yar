rule TTP_XOR_MULT_DOSStub_f7f3 {
  strings:
    $key_f7f3 = { a3 9b [2] d7 83 [2] 90 81 [2] d7 90 [2] 99 9c [2] 95 96 [2] 82 9d [2] 99 d3 [2] a4 }

  condition:
    any of them
}