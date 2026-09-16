rule TTP_XOR_MULT_DOSStub_8831 {
  strings:
    $key_8831 = { dc 59 [2] a8 41 [2] ef 43 [2] a8 52 [2] e6 5e [2] ea 54 [2] fd 5f [2] e6 11 [2] db }

  condition:
    any of them
}