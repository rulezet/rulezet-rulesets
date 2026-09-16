rule TTP_XOR_MULT_DOSStub_afa2 {
  strings:
    $key_afa2 = { fb ca [2] 8f d2 [2] c8 d0 [2] 8f c1 [2] c1 cd [2] cd c7 [2] da cc [2] c1 82 [2] fc }

  condition:
    any of them
}