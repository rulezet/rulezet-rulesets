rule TTP_XOR_MULT_DOSStub_88a5 {
  strings:
    $key_88a5 = { dc cd [2] a8 d5 [2] ef d7 [2] a8 c6 [2] e6 ca [2] ea c0 [2] fd cb [2] e6 85 [2] db }

  condition:
    any of them
}