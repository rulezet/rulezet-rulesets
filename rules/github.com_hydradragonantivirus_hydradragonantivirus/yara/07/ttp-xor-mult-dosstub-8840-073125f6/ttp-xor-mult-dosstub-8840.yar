rule TTP_XOR_MULT_DOSStub_8840 {
  strings:
    $key_8840 = { dc 28 [2] a8 30 [2] ef 32 [2] a8 23 [2] e6 2f [2] ea 25 [2] fd 2e [2] e6 60 [2] db }

  condition:
    any of them
}