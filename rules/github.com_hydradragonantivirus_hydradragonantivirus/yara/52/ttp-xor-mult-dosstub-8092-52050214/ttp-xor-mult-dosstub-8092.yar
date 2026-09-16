rule TTP_XOR_MULT_DOSStub_8092 {
  strings:
    $key_8092 = { d4 fa [2] a0 e2 [2] e7 e0 [2] a0 f1 [2] ee fd [2] e2 f7 [2] f5 fc [2] ee b2 [2] d3 }

  condition:
    any of them
}