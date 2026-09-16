rule TTP_XOR_MULT_DOSStub_886e {
  strings:
    $key_886e = { dc 06 [2] a8 1e [2] ef 1c [2] a8 0d [2] e6 01 [2] ea 0b [2] fd 00 [2] e6 4e [2] db }

  condition:
    any of them
}