rule TTP_XOR_MULT_DOSStub_88f3 {
  strings:
    $key_88f3 = { dc 9b [2] a8 83 [2] ef 81 [2] a8 90 [2] e6 9c [2] ea 96 [2] fd 9d [2] e6 d3 [2] db }

  condition:
    any of them
}