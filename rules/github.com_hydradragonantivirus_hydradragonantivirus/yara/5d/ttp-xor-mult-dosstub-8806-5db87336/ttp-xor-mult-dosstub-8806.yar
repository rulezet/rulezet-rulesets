rule TTP_XOR_MULT_DOSStub_8806 {
  strings:
    $key_8806 = { dc 6e [2] a8 76 [2] ef 74 [2] a8 65 [2] e6 69 [2] ea 63 [2] fd 68 [2] e6 26 [2] db }

  condition:
    any of them
}