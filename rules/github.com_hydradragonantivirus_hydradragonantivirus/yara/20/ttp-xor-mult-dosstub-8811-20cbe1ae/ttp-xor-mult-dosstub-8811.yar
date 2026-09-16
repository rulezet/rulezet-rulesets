rule TTP_XOR_MULT_DOSStub_8811 {
  strings:
    $key_8811 = { dc 79 [2] a8 61 [2] ef 63 [2] a8 72 [2] e6 7e [2] ea 74 [2] fd 7f [2] e6 31 [2] db }

  condition:
    any of them
}