rule TTP_XOR_MULT_DOSStub_88e7 {
  strings:
    $key_88e7 = { dc 8f [2] a8 97 [2] ef 95 [2] a8 84 [2] e6 88 [2] ea 82 [2] fd 89 [2] e6 c7 [2] db }

  condition:
    any of them
}