rule TTP_XOR_MULT_DOSStub_8839 {
  strings:
    $key_8839 = { dc 51 [2] a8 49 [2] ef 4b [2] a8 5a [2] e6 56 [2] ea 5c [2] fd 57 [2] e6 19 [2] db }

  condition:
    any of them
}