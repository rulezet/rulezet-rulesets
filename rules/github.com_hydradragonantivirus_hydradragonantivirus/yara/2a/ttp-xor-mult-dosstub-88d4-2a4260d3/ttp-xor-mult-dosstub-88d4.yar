rule TTP_XOR_MULT_DOSStub_88d4 {
  strings:
    $key_88d4 = { dc bc [2] a8 a4 [2] ef a6 [2] a8 b7 [2] e6 bb [2] ea b1 [2] fd ba [2] e6 f4 [2] db }

  condition:
    any of them
}