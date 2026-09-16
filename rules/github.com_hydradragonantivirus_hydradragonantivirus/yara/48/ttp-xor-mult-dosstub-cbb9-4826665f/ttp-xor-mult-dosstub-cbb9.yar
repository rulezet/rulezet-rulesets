rule TTP_XOR_MULT_DOSStub_cbb9 {
  strings:
    $key_cbb9 = { 9f d1 [2] eb c9 [2] ac cb [2] eb da [2] a5 d6 [2] a9 dc [2] be d7 [2] a5 99 [2] 98 }

  condition:
    any of them
}