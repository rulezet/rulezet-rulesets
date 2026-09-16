rule TTP_XOR_MULT_DOSStub_880a {
  strings:
    $key_880a = { dc 62 [2] a8 7a [2] ef 78 [2] a8 69 [2] e6 65 [2] ea 6f [2] fd 64 [2] e6 2a [2] db }

  condition:
    any of them
}