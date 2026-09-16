rule TTP_XOR_MULT_DOSStub_ede5 {
  strings:
    $key_ede5 = { b9 8d [2] cd 95 [2] 8a 97 [2] cd 86 [2] 83 8a [2] 8f 80 [2] 98 8b [2] 83 c5 [2] be }

  condition:
    any of them
}