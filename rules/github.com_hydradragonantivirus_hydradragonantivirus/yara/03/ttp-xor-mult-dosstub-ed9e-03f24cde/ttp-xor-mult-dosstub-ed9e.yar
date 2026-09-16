rule TTP_XOR_MULT_DOSStub_ed9e {
  strings:
    $key_ed9e = { b9 f6 [2] cd ee [2] 8a ec [2] cd fd [2] 83 f1 [2] 8f fb [2] 98 f0 [2] 83 be [2] be }

  condition:
    any of them
}