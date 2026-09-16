rule TTP_XOR_MULT_DOSStub_8862 {
  strings:
    $key_8862 = { dc 0a [2] a8 12 [2] ef 10 [2] a8 01 [2] e6 0d [2] ea 07 [2] fd 0c [2] e6 42 [2] db }

  condition:
    any of them
}