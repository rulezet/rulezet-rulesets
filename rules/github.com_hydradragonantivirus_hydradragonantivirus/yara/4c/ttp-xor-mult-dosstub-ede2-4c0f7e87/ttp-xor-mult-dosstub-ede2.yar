rule TTP_XOR_MULT_DOSStub_ede2 {
  strings:
    $key_ede2 = { b9 8a [2] cd 92 [2] 8a 90 [2] cd 81 [2] 83 8d [2] 8f 87 [2] 98 8c [2] 83 c2 [2] be }

  condition:
    any of them
}