rule TTP_XOR_MULT_DOSStub_8843 {
  strings:
    $key_8843 = { dc 2b [2] a8 33 [2] ef 31 [2] a8 20 [2] e6 2c [2] ea 26 [2] fd 2d [2] e6 63 [2] db }

  condition:
    any of them
}