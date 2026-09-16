rule TTP_XOR_MULT_DOSStub_883d {
  strings:
    $key_883d = { dc 55 [2] a8 4d [2] ef 4f [2] a8 5e [2] e6 52 [2] ea 58 [2] fd 53 [2] e6 1d [2] db }

  condition:
    any of them
}