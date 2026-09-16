rule TTP_XOR_MULT_DOSStub_884c {
  strings:
    $key_884c = { dc 24 [2] a8 3c [2] ef 3e [2] a8 2f [2] e6 23 [2] ea 29 [2] fd 22 [2] e6 6c [2] db }

  condition:
    any of them
}