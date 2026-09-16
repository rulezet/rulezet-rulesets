rule TTP_XOR_MULT_DOSStub_cbac {
  strings:
    $key_cbac = { 9f c4 [2] eb dc [2] ac de [2] eb cf [2] a5 c3 [2] a9 c9 [2] be c2 [2] a5 8c [2] 98 }

  condition:
    any of them
}