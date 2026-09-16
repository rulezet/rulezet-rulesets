rule TTP_XOR_MULT_DOSStub_afa3 {
  strings:
    $key_afa3 = { fb cb [2] 8f d3 [2] c8 d1 [2] 8f c0 [2] c1 cc [2] cd c6 [2] da cd [2] c1 83 [2] fc }

  condition:
    any of them
}