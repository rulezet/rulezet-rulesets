rule TTP_XOR_MULT_DOSStub_8f80 {
  strings:
    $key_8f80 = { db e8 [2] af f0 [2] e8 f2 [2] af e3 [2] e1 ef [2] ed e5 [2] fa ee [2] e1 a0 [2] dc }

  condition:
    any of them
}