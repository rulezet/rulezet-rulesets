rule TTP_XOR_MULT_DOSStub_ed70 {
  strings:
    $key_ed70 = { b9 18 [2] cd 00 [2] 8a 02 [2] cd 13 [2] 83 1f [2] 8f 15 [2] 98 1e [2] 83 50 [2] be }

  condition:
    any of them
}