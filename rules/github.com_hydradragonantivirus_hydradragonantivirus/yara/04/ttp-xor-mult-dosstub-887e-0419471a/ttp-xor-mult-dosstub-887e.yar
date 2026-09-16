rule TTP_XOR_MULT_DOSStub_887e {
  strings:
    $key_887e = { dc 16 [2] a8 0e [2] ef 0c [2] a8 1d [2] e6 11 [2] ea 1b [2] fd 10 [2] e6 5e [2] db }

  condition:
    any of them
}