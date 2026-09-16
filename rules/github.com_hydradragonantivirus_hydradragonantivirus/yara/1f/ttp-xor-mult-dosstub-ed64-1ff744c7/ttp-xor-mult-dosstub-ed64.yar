rule TTP_XOR_MULT_DOSStub_ed64 {
  strings:
    $key_ed64 = { b9 0c [2] cd 14 [2] 8a 16 [2] cd 07 [2] 83 0b [2] 8f 01 [2] 98 0a [2] 83 44 [2] be }

  condition:
    any of them
}