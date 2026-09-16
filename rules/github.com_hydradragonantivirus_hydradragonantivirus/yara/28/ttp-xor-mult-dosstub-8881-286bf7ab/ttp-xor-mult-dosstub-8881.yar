rule TTP_XOR_MULT_DOSStub_8881 {
  strings:
    $key_8881 = { dc e9 [2] a8 f1 [2] ef f3 [2] a8 e2 [2] e6 ee [2] ea e4 [2] fd ef [2] e6 a1 [2] db }

  condition:
    any of them
}