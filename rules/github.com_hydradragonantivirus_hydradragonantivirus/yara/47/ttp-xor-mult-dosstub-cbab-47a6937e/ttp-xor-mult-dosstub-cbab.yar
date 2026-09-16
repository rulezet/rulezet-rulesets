rule TTP_XOR_MULT_DOSStub_cbab {
  strings:
    $key_cbab = { 9f c3 [2] eb db [2] ac d9 [2] eb c8 [2] a5 c4 [2] a9 ce [2] be c5 [2] a5 8b [2] 98 }

  condition:
    any of them
}