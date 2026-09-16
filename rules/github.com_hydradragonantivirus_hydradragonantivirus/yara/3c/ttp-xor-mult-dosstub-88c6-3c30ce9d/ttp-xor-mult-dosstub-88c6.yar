rule TTP_XOR_MULT_DOSStub_88c6 {
  strings:
    $key_88c6 = { dc ae [2] a8 b6 [2] ef b4 [2] a8 a5 [2] e6 a9 [2] ea a3 [2] fd a8 [2] e6 e6 [2] db }

  condition:
    any of them
}