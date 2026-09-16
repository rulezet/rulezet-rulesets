rule TTP_XOR_MULT_DOSStub_afab {
  strings:
    $key_afab = { fb c3 [2] 8f db [2] c8 d9 [2] 8f c8 [2] c1 c4 [2] cd ce [2] da c5 [2] c1 8b [2] fc }

  condition:
    any of them
}