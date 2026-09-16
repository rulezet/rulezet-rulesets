rule TTP_XOR_MULT_DOSStub_88e6 {
  strings:
    $key_88e6 = { dc 8e [2] a8 96 [2] ef 94 [2] a8 85 [2] e6 89 [2] ea 83 [2] fd 88 [2] e6 c6 [2] db }

  condition:
    any of them
}