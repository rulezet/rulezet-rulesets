rule TTP_XOR_MULT_DOSStub_88f8 {
  strings:
    $key_88f8 = { dc 90 [2] a8 88 [2] ef 8a [2] a8 9b [2] e6 97 [2] ea 9d [2] fd 96 [2] e6 d8 [2] db }

  condition:
    any of them
}