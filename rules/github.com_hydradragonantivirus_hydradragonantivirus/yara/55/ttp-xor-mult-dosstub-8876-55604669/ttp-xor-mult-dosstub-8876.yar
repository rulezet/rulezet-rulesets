rule TTP_XOR_MULT_DOSStub_8876 {
  strings:
    $key_8876 = { dc 1e [2] a8 06 [2] ef 04 [2] a8 15 [2] e6 19 [2] ea 13 [2] fd 18 [2] e6 56 [2] db }

  condition:
    any of them
}