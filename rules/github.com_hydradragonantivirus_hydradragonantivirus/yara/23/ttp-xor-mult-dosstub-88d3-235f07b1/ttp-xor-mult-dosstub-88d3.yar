rule TTP_XOR_MULT_DOSStub_88d3 {
  strings:
    $key_88d3 = { dc bb [2] a8 a3 [2] ef a1 [2] a8 b0 [2] e6 bc [2] ea b6 [2] fd bd [2] e6 f3 [2] db }

  condition:
    any of them
}