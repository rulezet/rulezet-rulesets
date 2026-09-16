rule TTP_XOR_MULT_DOSStub_88d7 {
  strings:
    $key_88d7 = { dc bf [2] a8 a7 [2] ef a5 [2] a8 b4 [2] e6 b8 [2] ea b2 [2] fd b9 [2] e6 f7 [2] db }

  condition:
    any of them
}