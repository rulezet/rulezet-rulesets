rule TTP_XOR_MULT_DOSStub_ed72 {
  strings:
    $key_ed72 = { b9 1a [2] cd 02 [2] 8a 00 [2] cd 11 [2] 83 1d [2] 8f 17 [2] 98 1c [2] 83 52 [2] be }

  condition:
    any of them
}