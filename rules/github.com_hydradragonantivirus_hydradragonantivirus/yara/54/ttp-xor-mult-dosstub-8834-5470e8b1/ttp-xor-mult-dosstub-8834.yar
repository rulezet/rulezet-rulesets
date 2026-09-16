rule TTP_XOR_MULT_DOSStub_8834 {
  strings:
    $key_8834 = { dc 5c [2] a8 44 [2] ef 46 [2] a8 57 [2] e6 5b [2] ea 51 [2] fd 5a [2] e6 14 [2] db }

  condition:
    any of them
}