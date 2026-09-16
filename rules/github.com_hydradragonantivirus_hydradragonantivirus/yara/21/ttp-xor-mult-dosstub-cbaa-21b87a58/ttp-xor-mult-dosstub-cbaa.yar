rule TTP_XOR_MULT_DOSStub_cbaa {
  strings:
    $key_cbaa = { 9f c2 [2] eb da [2] ac d8 [2] eb c9 [2] a5 c5 [2] a9 cf [2] be c4 [2] a5 8a [2] 98 }

  condition:
    any of them
}