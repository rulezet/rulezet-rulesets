rule TTP_XOR_MULT_DOSStub_ed77 {
  strings:
    $key_ed77 = { b9 1f [2] cd 07 [2] 8a 05 [2] cd 14 [2] 83 18 [2] 8f 12 [2] 98 19 [2] 83 57 [2] be }

  condition:
    any of them
}