rule TTP_XOR_MULT_DOSStub_881b {
  strings:
    $key_881b = { dc 73 [2] a8 6b [2] ef 69 [2] a8 78 [2] e6 74 [2] ea 7e [2] fd 75 [2] e6 3b [2] db }

  condition:
    any of them
}