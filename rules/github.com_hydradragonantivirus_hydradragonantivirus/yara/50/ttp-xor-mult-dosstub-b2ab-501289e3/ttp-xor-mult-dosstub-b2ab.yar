rule TTP_XOR_MULT_DOSStub_b2ab {
  strings:
    $key_b2ab = { e6 c3 [2] 92 db [2] d5 d9 [2] 92 c8 [2] dc c4 [2] d0 ce [2] c7 c5 [2] dc 8b [2] e1 }

  condition:
    any of them
}