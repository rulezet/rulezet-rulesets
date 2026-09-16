rule TTP_XOR_MULT_DOSStub_8871 {
  strings:
    $key_8871 = { dc 19 [2] a8 01 [2] ef 03 [2] a8 12 [2] e6 1e [2] ea 14 [2] fd 1f [2] e6 51 [2] db }

  condition:
    any of them
}