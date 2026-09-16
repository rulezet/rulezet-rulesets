rule TTP_XOR_MULT_DOSStub_885a {
  strings:
    $key_885a = { dc 32 [2] a8 2a [2] ef 28 [2] a8 39 [2] e6 35 [2] ea 3f [2] fd 34 [2] e6 7a [2] db }

  condition:
    any of them
}