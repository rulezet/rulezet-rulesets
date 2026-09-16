rule TTP_XOR_MULT_DOSStub_8864 {
  strings:
    $key_8864 = { dc 0c [2] a8 14 [2] ef 16 [2] a8 07 [2] e6 0b [2] ea 01 [2] fd 0a [2] e6 44 [2] db }

  condition:
    any of them
}