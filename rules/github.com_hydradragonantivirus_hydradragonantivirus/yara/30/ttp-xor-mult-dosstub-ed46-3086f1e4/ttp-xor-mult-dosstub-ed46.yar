rule TTP_XOR_MULT_DOSStub_ed46 {
  strings:
    $key_ed46 = { b9 2e [2] cd 36 [2] 8a 34 [2] cd 25 [2] 83 29 [2] 8f 23 [2] 98 28 [2] 83 66 [2] be }

  condition:
    any of them
}