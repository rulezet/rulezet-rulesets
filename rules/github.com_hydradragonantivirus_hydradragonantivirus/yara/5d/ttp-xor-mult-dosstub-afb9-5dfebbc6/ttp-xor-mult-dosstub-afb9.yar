rule TTP_XOR_MULT_DOSStub_afb9 {
  strings:
    $key_afb9 = { fb d1 [2] 8f c9 [2] c8 cb [2] 8f da [2] c1 d6 [2] cd dc [2] da d7 [2] c1 99 [2] fc }

  condition:
    any of them
}