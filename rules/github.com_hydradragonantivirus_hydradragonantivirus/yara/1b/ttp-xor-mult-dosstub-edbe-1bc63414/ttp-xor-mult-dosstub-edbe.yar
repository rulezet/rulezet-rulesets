rule TTP_XOR_MULT_DOSStub_edbe {
  strings:
    $key_edbe = { b9 d6 [2] cd ce [2] 8a cc [2] cd dd [2] 83 d1 [2] 8f db [2] 98 d0 [2] 83 9e [2] be }

  condition:
    any of them
}