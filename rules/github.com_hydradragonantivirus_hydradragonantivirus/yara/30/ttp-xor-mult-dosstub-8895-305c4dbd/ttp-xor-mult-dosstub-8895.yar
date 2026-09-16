rule TTP_XOR_MULT_DOSStub_8895 {
  strings:
    $key_8895 = { dc fd [2] a8 e5 [2] ef e7 [2] a8 f6 [2] e6 fa [2] ea f0 [2] fd fb [2] e6 b5 [2] db }

  condition:
    any of them
}