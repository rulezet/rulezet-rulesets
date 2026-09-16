rule TTP_XOR_MULT_DOSStub_edd5 {
  strings:
    $key_edd5 = { b9 bd [2] cd a5 [2] 8a a7 [2] cd b6 [2] 83 ba [2] 8f b0 [2] 98 bb [2] 83 f5 [2] be }

  condition:
    any of them
}