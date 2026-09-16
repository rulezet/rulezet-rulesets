rule TTP_XOR_MULT_DOSStub_88b4 {
  strings:
    $key_88b4 = { dc dc [2] a8 c4 [2] ef c6 [2] a8 d7 [2] e6 db [2] ea d1 [2] fd da [2] e6 94 [2] db }

  condition:
    any of them
}