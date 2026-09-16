rule TTP_XOR_MULT_DOSStub_eda9 {
  strings:
    $key_eda9 = { b9 c1 [2] cd d9 [2] 8a db [2] cd ca [2] 83 c6 [2] 8f cc [2] 98 c7 [2] 83 89 [2] be }

  condition:
    any of them
}