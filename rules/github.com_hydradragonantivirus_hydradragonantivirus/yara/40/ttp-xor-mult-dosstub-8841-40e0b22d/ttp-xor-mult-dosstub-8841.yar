rule TTP_XOR_MULT_DOSStub_8841 {
  strings:
    $key_8841 = { dc 29 [2] a8 31 [2] ef 33 [2] a8 22 [2] e6 2e [2] ea 24 [2] fd 2f [2] e6 61 [2] db }

  condition:
    any of them
}