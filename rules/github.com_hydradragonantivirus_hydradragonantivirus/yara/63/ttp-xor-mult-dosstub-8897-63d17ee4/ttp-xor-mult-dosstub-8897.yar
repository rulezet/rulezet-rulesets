rule TTP_XOR_MULT_DOSStub_8897 {
  strings:
    $key_8897 = { dc ff [2] a8 e7 [2] ef e5 [2] a8 f4 [2] e6 f8 [2] ea f2 [2] fd f9 [2] e6 b7 [2] db }

  condition:
    any of them
}