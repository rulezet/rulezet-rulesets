rule TTP_XOR_MULT_DOSStub_ed65 {
  strings:
    $key_ed65 = { b9 0d [2] cd 15 [2] 8a 17 [2] cd 06 [2] 83 0a [2] 8f 00 [2] 98 0b [2] 83 45 [2] be }

  condition:
    any of them
}