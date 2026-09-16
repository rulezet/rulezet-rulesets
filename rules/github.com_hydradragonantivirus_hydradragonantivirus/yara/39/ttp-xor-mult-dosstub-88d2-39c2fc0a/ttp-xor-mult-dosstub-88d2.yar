rule TTP_XOR_MULT_DOSStub_88d2 {
  strings:
    $key_88d2 = { dc ba [2] a8 a2 [2] ef a0 [2] a8 b1 [2] e6 bd [2] ea b7 [2] fd bc [2] e6 f2 [2] db }

  condition:
    any of them
}