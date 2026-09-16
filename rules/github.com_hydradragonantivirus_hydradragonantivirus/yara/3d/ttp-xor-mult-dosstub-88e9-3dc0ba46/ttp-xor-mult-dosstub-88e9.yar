rule TTP_XOR_MULT_DOSStub_88e9 {
  strings:
    $key_88e9 = { dc 81 [2] a8 99 [2] ef 9b [2] a8 8a [2] e6 86 [2] ea 8c [2] fd 87 [2] e6 c9 [2] db }

  condition:
    any of them
}