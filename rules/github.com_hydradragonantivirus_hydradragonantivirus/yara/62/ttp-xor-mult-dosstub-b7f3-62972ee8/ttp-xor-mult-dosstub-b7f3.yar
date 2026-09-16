rule TTP_XOR_MULT_DOSStub_b7f3 {
  strings:
    $key_b7f3 = { e3 9b [2] 97 83 [2] d0 81 [2] 97 90 [2] d9 9c [2] d5 96 [2] c2 9d [2] d9 d3 [2] e4 }

  condition:
    any of them
}