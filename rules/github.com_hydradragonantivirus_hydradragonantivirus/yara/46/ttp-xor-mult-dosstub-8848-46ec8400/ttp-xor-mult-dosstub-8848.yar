rule TTP_XOR_MULT_DOSStub_8848 {
  strings:
    $key_8848 = { dc 20 [2] a8 38 [2] ef 3a [2] a8 2b [2] e6 27 [2] ea 2d [2] fd 26 [2] e6 68 [2] db }

  condition:
    any of them
}