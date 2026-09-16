rule TTP_XOR_MULT_DOSStub_ede4 {
  strings:
    $key_ede4 = { b9 8c [2] cd 94 [2] 8a 96 [2] cd 87 [2] 83 8b [2] 8f 81 [2] 98 8a [2] 83 c4 [2] be }

  condition:
    any of them
}