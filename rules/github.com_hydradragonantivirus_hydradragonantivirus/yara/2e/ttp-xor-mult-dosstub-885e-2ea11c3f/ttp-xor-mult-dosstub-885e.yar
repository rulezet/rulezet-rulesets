rule TTP_XOR_MULT_DOSStub_885e {
  strings:
    $key_885e = { dc 36 [2] a8 2e [2] ef 2c [2] a8 3d [2] e6 31 [2] ea 3b [2] fd 30 [2] e6 7e [2] db }

  condition:
    any of them
}