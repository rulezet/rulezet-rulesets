rule TTP_XOR_MULT_DOSStub_885d {
  strings:
    $key_885d = { dc 35 [2] a8 2d [2] ef 2f [2] a8 3e [2] e6 32 [2] ea 38 [2] fd 33 [2] e6 7d [2] db }

  condition:
    any of them
}