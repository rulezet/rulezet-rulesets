rule TTP_XOR_MULT_DOSStub_edda {
  strings:
    $key_edda = { b9 b2 [2] cd aa [2] 8a a8 [2] cd b9 [2] 83 b5 [2] 8f bf [2] 98 b4 [2] 83 fa [2] be }

  condition:
    any of them
}