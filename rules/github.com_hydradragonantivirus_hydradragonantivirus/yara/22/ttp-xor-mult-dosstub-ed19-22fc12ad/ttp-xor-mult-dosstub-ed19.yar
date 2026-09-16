rule TTP_XOR_MULT_DOSStub_ed19 {
  strings:
    $key_ed19 = { b9 71 [2] cd 69 [2] 8a 6b [2] cd 7a [2] 83 76 [2] 8f 7c [2] 98 77 [2] 83 39 [2] be }

  condition:
    any of them
}