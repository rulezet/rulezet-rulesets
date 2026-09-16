rule TTP_XOR_MULT_DOSStub_8854 {
  strings:
    $key_8854 = { dc 3c [2] a8 24 [2] ef 26 [2] a8 37 [2] e6 3b [2] ea 31 [2] fd 3a [2] e6 74 [2] db }

  condition:
    any of them
}