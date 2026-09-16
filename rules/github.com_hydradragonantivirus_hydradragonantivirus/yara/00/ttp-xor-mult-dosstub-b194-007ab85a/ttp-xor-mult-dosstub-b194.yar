rule TTP_XOR_MULT_DOSStub_b194 {
  strings:
    $key_b194 = { e5 fc [2] 91 e4 [2] d6 e6 [2] 91 f7 [2] df fb [2] d3 f1 [2] c4 fa [2] df b4 [2] e2 }

  condition:
    any of them
}