rule TTP_XOR_MULT_DOSStub_edb2 {
  strings:
    $key_edb2 = { b9 da [2] cd c2 [2] 8a c0 [2] cd d1 [2] 83 dd [2] 8f d7 [2] 98 dc [2] 83 92 [2] be }

  condition:
    any of them
}