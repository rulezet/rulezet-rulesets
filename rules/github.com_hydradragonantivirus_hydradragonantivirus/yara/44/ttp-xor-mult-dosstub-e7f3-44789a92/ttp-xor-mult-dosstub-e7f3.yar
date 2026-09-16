rule TTP_XOR_MULT_DOSStub_e7f3 {
  strings:
    $key_e7f3 = { b3 9b [2] c7 83 [2] 80 81 [2] c7 90 [2] 89 9c [2] 85 96 [2] 92 9d [2] 89 d3 [2] b4 }

  condition:
    any of them
}