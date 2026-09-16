rule TTP_XOR_MULT_DOSStub_8874 {
  strings:
    $key_8874 = { dc 1c [2] a8 04 [2] ef 06 [2] a8 17 [2] e6 1b [2] ea 11 [2] fd 1a [2] e6 54 [2] db }

  condition:
    any of them
}