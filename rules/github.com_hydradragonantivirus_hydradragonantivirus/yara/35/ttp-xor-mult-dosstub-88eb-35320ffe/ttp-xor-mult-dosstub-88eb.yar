rule TTP_XOR_MULT_DOSStub_88eb {
  strings:
    $key_88eb = { dc 83 [2] a8 9b [2] ef 99 [2] a8 88 [2] e6 84 [2] ea 8e [2] fd 85 [2] e6 cb [2] db }

  condition:
    any of them
}