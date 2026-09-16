rule TTP_XOR_MULT_DOSStub_88f7 {
  strings:
    $key_88f7 = { dc 9f [2] a8 87 [2] ef 85 [2] a8 94 [2] e6 98 [2] ea 92 [2] fd 99 [2] e6 d7 [2] db }

  condition:
    any of them
}