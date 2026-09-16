rule TTP_XOR_MULT_DOSStub_887b {
  strings:
    $key_887b = { dc 13 [2] a8 0b [2] ef 09 [2] a8 18 [2] e6 14 [2] ea 1e [2] fd 15 [2] e6 5b [2] db }

  condition:
    any of them
}