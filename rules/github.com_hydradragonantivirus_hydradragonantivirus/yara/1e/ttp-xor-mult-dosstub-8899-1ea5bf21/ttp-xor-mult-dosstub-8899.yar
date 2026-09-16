rule TTP_XOR_MULT_DOSStub_8899 {
  strings:
    $key_8899 = { dc f1 [2] a8 e9 [2] ef eb [2] a8 fa [2] e6 f6 [2] ea fc [2] fd f7 [2] e6 b9 [2] db }

  condition:
    any of them
}