rule TTP_XOR_MULT_DOSStub_88e3 {
  strings:
    $key_88e3 = { dc 8b [2] a8 93 [2] ef 91 [2] a8 80 [2] e6 8c [2] ea 86 [2] fd 8d [2] e6 c3 [2] db }

  condition:
    any of them
}