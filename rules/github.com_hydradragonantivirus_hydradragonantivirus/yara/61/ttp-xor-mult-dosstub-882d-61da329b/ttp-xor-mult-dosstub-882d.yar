rule TTP_XOR_MULT_DOSStub_882d {
  strings:
    $key_882d = { dc 45 [2] a8 5d [2] ef 5f [2] a8 4e [2] e6 42 [2] ea 48 [2] fd 43 [2] e6 0d [2] db }

  condition:
    any of them
}