rule TTP_XOR_MULT_DOSStub_882c {
  strings:
    $key_882c = { dc 44 [2] a8 5c [2] ef 5e [2] a8 4f [2] e6 43 [2] ea 49 [2] fd 42 [2] e6 0c [2] db }

  condition:
    any of them
}