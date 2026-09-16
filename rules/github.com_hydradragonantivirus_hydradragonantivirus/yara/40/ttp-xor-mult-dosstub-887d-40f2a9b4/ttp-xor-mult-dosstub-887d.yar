rule TTP_XOR_MULT_DOSStub_887d {
  strings:
    $key_887d = { dc 15 [2] a8 0d [2] ef 0f [2] a8 1e [2] e6 12 [2] ea 18 [2] fd 13 [2] e6 5d [2] db }

  condition:
    any of them
}