rule TTP_XOR_MULT_DOSStub_8999 {
  strings:
    $key_8999 = { dd f1 [2] a9 e9 [2] ee eb [2] a9 fa [2] e7 f6 [2] eb fc [2] fc f7 [2] e7 b9 [2] da }

  condition:
    any of them
}