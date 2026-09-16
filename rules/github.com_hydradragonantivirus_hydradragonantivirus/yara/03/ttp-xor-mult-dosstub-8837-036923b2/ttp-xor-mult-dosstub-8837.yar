rule TTP_XOR_MULT_DOSStub_8837 {
  strings:
    $key_8837 = { dc 5f [2] a8 47 [2] ef 45 [2] a8 54 [2] e6 58 [2] ea 52 [2] fd 59 [2] e6 17 [2] db }

  condition:
    any of them
}