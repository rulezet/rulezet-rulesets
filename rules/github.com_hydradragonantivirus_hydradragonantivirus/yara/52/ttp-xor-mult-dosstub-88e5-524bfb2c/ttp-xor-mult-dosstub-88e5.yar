rule TTP_XOR_MULT_DOSStub_88e5 {
  strings:
    $key_88e5 = { dc 8d [2] a8 95 [2] ef 97 [2] a8 86 [2] e6 8a [2] ea 80 [2] fd 8b [2] e6 c5 [2] db }

  condition:
    any of them
}