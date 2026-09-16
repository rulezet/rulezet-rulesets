rule TTP_XOR_MULT_DOSStub_b2a9 {
  strings:
    $key_b2a9 = { e6 c1 [2] 92 d9 [2] d5 db [2] 92 ca [2] dc c6 [2] d0 cc [2] c7 c7 [2] dc 89 [2] e1 }

  condition:
    any of them
}