rule TTP_XOR_MULT_DOSStub_8842 {
  strings:
    $key_8842 = { dc 2a [2] a8 32 [2] ef 30 [2] a8 21 [2] e6 2d [2] ea 27 [2] fd 2c [2] e6 62 [2] db }

  condition:
    any of them
}