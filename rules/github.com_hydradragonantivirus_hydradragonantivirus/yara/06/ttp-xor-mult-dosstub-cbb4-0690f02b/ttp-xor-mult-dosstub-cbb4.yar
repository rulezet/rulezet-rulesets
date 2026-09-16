rule TTP_XOR_MULT_DOSStub_cbb4 {
  strings:
    $key_cbb4 = { 9f dc [2] eb c4 [2] ac c6 [2] eb d7 [2] a5 db [2] a9 d1 [2] be da [2] a5 94 [2] 98 }

  condition:
    any of them
}