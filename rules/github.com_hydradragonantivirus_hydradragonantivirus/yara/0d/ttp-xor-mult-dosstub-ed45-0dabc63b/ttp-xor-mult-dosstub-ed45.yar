rule TTP_XOR_MULT_DOSStub_ed45 {
  strings:
    $key_ed45 = { b9 2d [2] cd 35 [2] 8a 37 [2] cd 26 [2] 83 2a [2] 8f 20 [2] 98 2b [2] 83 65 [2] be }

  condition:
    any of them
}