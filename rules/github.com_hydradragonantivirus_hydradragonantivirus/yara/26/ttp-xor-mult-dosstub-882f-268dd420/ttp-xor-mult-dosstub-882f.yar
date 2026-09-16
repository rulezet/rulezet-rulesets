rule TTP_XOR_MULT_DOSStub_882f {
  strings:
    $key_882f = { dc 47 [2] a8 5f [2] ef 5d [2] a8 4c [2] e6 40 [2] ea 4a [2] fd 41 [2] e6 0f [2] db }

  condition:
    any of them
}