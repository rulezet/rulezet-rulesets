rule TTP_XOR_MULT_DOSStub_883a {
  strings:
    $key_883a = { dc 52 [2] a8 4a [2] ef 48 [2] a8 59 [2] e6 55 [2] ea 5f [2] fd 54 [2] e6 1a [2] db }

  condition:
    any of them
}