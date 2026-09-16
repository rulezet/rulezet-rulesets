rule TTP_XOR_MULT_DOSStub_ed34 {
  strings:
    $key_ed34 = { b9 5c [2] cd 44 [2] 8a 46 [2] cd 57 [2] 83 5b [2] 8f 51 [2] 98 5a [2] 83 14 [2] be }

  condition:
    any of them
}