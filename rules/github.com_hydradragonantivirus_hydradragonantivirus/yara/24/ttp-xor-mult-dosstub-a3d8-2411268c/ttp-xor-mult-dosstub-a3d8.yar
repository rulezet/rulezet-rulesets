rule TTP_XOR_MULT_DOSStub_a3d8 {
  strings:
    $key_a3d8 = { f7 b0 [2] 83 a8 [2] c4 aa [2] 83 bb [2] cd b7 [2] c1 bd [2] d6 b6 [2] cd f8 [2] f0 }

  condition:
    any of them
}