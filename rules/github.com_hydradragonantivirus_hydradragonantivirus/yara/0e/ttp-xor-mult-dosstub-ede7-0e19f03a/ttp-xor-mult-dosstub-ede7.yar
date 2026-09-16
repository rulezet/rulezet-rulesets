rule TTP_XOR_MULT_DOSStub_ede7 {
  strings:
    $key_ede7 = { b9 8f [2] cd 97 [2] 8a 95 [2] cd 84 [2] 83 88 [2] 8f 82 [2] 98 89 [2] 83 c7 [2] be }

  condition:
    any of them
}