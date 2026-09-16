rule TTP_XOR_MULT_DOSStub_edb9 {
  strings:
    $key_edb9 = { b9 d1 [2] cd c9 [2] 8a cb [2] cd da [2] 83 d6 [2] 8f dc [2] 98 d7 [2] 83 99 [2] be }

  condition:
    any of them
}