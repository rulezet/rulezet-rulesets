rule TTP_XOR_MULT_DOSStub_8799 {
  strings:
    $key_8799 = { d3 f1 [2] a7 e9 [2] e0 eb [2] a7 fa [2] e9 f6 [2] e5 fc [2] f2 f7 [2] e9 b9 [2] d4 }

  condition:
    any of them
}