rule TTP_XOR_MULT_DOSStub_afa4 {
  strings:
    $key_afa4 = { fb cc [2] 8f d4 [2] c8 d6 [2] 8f c7 [2] c1 cb [2] cd c1 [2] da ca [2] c1 84 [2] fc }

  condition:
    any of them
}