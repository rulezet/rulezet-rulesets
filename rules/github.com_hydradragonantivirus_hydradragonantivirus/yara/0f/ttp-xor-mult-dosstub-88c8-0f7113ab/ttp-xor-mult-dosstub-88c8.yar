rule TTP_XOR_MULT_DOSStub_88c8 {
  strings:
    $key_88c8 = { dc a0 [2] a8 b8 [2] ef ba [2] a8 ab [2] e6 a7 [2] ea ad [2] fd a6 [2] e6 e8 [2] db }

  condition:
    any of them
}