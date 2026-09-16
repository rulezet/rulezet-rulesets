rule TTP_XOR_MULT_DOSStub_ed33 {
  strings:
    $key_ed33 = { b9 5b [2] cd 43 [2] 8a 41 [2] cd 50 [2] 83 5c [2] 8f 56 [2] 98 5d [2] 83 13 [2] be }

  condition:
    any of them
}