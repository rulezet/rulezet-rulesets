rule TTP_XOR_MULT_DOSStub_88f9 {
  strings:
    $key_88f9 = { dc 91 [2] a8 89 [2] ef 8b [2] a8 9a [2] e6 96 [2] ea 9c [2] fd 97 [2] e6 d9 [2] db }

  condition:
    any of them
}