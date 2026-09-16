rule TTP_XOR_MULT_DOSStub_8816 {
  strings:
    $key_8816 = { dc 7e [2] a8 66 [2] ef 64 [2] a8 75 [2] e6 79 [2] ea 73 [2] fd 78 [2] e6 36 [2] db }

  condition:
    any of them
}