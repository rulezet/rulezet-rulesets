rule TTP_XOR_MULT_DOSStub_8846 {
  strings:
    $key_8846 = { dc 2e [2] a8 36 [2] ef 34 [2] a8 25 [2] e6 29 [2] ea 23 [2] fd 28 [2] e6 66 [2] db }

  condition:
    any of them
}