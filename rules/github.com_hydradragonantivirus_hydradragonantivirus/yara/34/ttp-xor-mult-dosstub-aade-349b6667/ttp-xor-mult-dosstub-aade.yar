rule TTP_XOR_MULT_DOSStub_aade {
  strings:
    $key_aade = { fe b6 [2] 8a ae [2] cd ac [2] 8a bd [2] c4 b1 [2] c8 bb [2] df b0 [2] c4 fe [2] f9 }

  condition:
    any of them
}