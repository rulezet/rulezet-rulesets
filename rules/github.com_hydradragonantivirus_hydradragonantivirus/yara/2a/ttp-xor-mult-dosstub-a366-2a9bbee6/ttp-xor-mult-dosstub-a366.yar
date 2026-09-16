rule TTP_XOR_MULT_DOSStub_a366 {
  strings:
    $key_a366 = { f7 0e [2] 83 16 [2] c4 14 [2] 83 05 [2] cd 09 [2] c1 03 [2] d6 08 [2] cd 46 [2] f0 }

  condition:
    any of them
}