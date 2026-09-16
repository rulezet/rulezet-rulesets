rule TTP_XOR_MULT_DOSStub_88e1 {
  strings:
    $key_88e1 = { dc 89 [2] a8 91 [2] ef 93 [2] a8 82 [2] e6 8e [2] ea 84 [2] fd 8f [2] e6 c1 [2] db }

  condition:
    any of them
}