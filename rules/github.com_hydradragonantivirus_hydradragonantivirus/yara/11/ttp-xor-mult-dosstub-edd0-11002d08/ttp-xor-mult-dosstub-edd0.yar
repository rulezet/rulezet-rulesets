rule TTP_XOR_MULT_DOSStub_edd0 {
  strings:
    $key_edd0 = { b9 b8 [2] cd a0 [2] 8a a2 [2] cd b3 [2] 83 bf [2] 8f b5 [2] 98 be [2] 83 f0 [2] be }

  condition:
    any of them
}