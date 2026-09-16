rule TTP_XOR_MULT_DOSStub_e5f3 {
  strings:
    $key_e5f3 = { b1 9b [2] c5 83 [2] 82 81 [2] c5 90 [2] 8b 9c [2] 87 96 [2] 90 9d [2] 8b d3 [2] b6 }

  condition:
    any of them
}