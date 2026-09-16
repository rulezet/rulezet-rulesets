rule TTP_XOR_MULT_DOSStub_8804 {
  strings:
    $key_8804 = { dc 6c [2] a8 74 [2] ef 76 [2] a8 67 [2] e6 6b [2] ea 61 [2] fd 6a [2] e6 24 [2] db }

  condition:
    any of them
}