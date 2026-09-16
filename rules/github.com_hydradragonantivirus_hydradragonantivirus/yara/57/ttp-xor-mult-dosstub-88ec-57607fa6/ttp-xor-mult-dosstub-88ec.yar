rule TTP_XOR_MULT_DOSStub_88ec {
  strings:
    $key_88ec = { dc 84 [2] a8 9c [2] ef 9e [2] a8 8f [2] e6 83 [2] ea 89 [2] fd 82 [2] e6 cc [2] db }

  condition:
    any of them
}