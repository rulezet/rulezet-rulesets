rule TTP_XOR_MULT_DOSStub_e1f3 {
  strings:
    $key_e1f3 = { b5 9b [2] c1 83 [2] 86 81 [2] c1 90 [2] 8f 9c [2] 83 96 [2] 94 9d [2] 8f d3 [2] b2 }

  condition:
    any of them
}