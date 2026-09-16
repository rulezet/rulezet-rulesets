rule TTP_XOR_MULT_DOSStub_8836 {
  strings:
    $key_8836 = { dc 5e [2] a8 46 [2] ef 44 [2] a8 55 [2] e6 59 [2] ea 53 [2] fd 58 [2] e6 16 [2] db }

  condition:
    any of them
}