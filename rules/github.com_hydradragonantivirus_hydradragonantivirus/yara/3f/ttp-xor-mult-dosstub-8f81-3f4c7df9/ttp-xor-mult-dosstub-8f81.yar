rule TTP_XOR_MULT_DOSStub_8f81 {
  strings:
    $key_8f81 = { db e9 [2] af f1 [2] e8 f3 [2] af e2 [2] e1 ee [2] ed e4 [2] fa ef [2] e1 a1 [2] dc }

  condition:
    any of them
}