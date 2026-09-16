rule TTP_XOR_MULT_DOSStub_881a {
  strings:
    $key_881a = { dc 72 [2] a8 6a [2] ef 68 [2] a8 79 [2] e6 75 [2] ea 7f [2] fd 74 [2] e6 3a [2] db }

  condition:
    any of them
}