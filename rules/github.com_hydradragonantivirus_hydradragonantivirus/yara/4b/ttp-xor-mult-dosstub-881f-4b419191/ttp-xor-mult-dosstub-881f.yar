rule TTP_XOR_MULT_DOSStub_881f {
  strings:
    $key_881f = { dc 77 [2] a8 6f [2] ef 6d [2] a8 7c [2] e6 70 [2] ea 7a [2] fd 71 [2] e6 3f [2] db }

  condition:
    any of them
}