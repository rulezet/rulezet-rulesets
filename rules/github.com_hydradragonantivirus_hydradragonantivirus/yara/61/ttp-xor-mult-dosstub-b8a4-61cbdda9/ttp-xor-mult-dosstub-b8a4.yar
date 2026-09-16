rule TTP_XOR_MULT_DOSStub_b8a4 {
  strings:
    $key_b8a4 = { ec cc [2] 98 d4 [2] df d6 [2] 98 c7 [2] d6 cb [2] da c1 [2] cd ca [2] d6 84 [2] eb }

  condition:
    any of them
}