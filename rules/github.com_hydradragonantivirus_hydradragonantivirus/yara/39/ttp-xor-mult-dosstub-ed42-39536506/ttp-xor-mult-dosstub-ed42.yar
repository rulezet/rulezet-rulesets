rule TTP_XOR_MULT_DOSStub_ed42 {
  strings:
    $key_ed42 = { b9 2a [2] cd 32 [2] 8a 30 [2] cd 21 [2] 83 2d [2] 8f 27 [2] 98 2c [2] 83 62 [2] be }

  condition:
    any of them
}