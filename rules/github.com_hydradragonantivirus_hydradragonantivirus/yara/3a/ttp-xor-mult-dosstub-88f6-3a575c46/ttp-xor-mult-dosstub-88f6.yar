rule TTP_XOR_MULT_DOSStub_88f6 {
  strings:
    $key_88f6 = { dc 9e [2] a8 86 [2] ef 84 [2] a8 95 [2] e6 99 [2] ea 93 [2] fd 98 [2] e6 d6 [2] db }

  condition:
    any of them
}