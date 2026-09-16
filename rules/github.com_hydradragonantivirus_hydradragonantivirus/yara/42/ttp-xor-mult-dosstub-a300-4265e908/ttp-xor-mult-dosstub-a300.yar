rule TTP_XOR_MULT_DOSStub_a300 {
  strings:
    $key_a300 = { f7 68 [2] 83 70 [2] c4 72 [2] 83 63 [2] cd 6f [2] c1 65 [2] d6 6e [2] cd 20 [2] f0 }

  condition:
    any of them
}