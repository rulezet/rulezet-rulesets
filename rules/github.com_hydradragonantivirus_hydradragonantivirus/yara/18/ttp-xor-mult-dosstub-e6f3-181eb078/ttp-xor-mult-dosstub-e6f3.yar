rule TTP_XOR_MULT_DOSStub_e6f3 {
  strings:
    $key_e6f3 = { b2 9b [2] c6 83 [2] 81 81 [2] c6 90 [2] 88 9c [2] 84 96 [2] 93 9d [2] 88 d3 [2] b5 }

  condition:
    any of them
}