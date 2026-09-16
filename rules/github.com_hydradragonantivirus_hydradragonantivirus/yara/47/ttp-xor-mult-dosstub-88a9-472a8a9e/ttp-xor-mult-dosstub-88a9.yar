rule TTP_XOR_MULT_DOSStub_88a9 {
  strings:
    $key_88a9 = { dc c1 [2] a8 d9 [2] ef db [2] a8 ca [2] e6 c6 [2] ea cc [2] fd c7 [2] e6 89 [2] db }

  condition:
    any of them
}