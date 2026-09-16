rule TTP_XOR_MULT_DOSStub_ed39 {
  strings:
    $key_ed39 = { b9 51 [2] cd 49 [2] 8a 4b [2] cd 5a [2] 83 56 [2] 8f 5c [2] 98 57 [2] 83 19 [2] be }

  condition:
    any of them
}