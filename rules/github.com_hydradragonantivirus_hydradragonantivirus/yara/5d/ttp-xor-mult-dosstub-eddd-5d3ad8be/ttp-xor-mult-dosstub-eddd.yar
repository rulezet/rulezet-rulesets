rule TTP_XOR_MULT_DOSStub_eddd {
  strings:
    $key_eddd = { b9 b5 [2] cd ad [2] 8a af [2] cd be [2] 83 b2 [2] 8f b8 [2] 98 b3 [2] 83 fd [2] be }

  condition:
    any of them
}