rule TTP_XOR_MULT_DOSStub_ed68 {
  strings:
    $key_ed68 = { b9 00 [2] cd 18 [2] 8a 1a [2] cd 0b [2] 83 07 [2] 8f 0d [2] 98 06 [2] 83 48 [2] be }

  condition:
    any of them
}