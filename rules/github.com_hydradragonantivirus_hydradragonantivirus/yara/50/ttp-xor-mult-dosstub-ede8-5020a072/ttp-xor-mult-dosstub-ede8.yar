rule TTP_XOR_MULT_DOSStub_ede8 {
  strings:
    $key_ede8 = { b9 80 [2] cd 98 [2] 8a 9a [2] cd 8b [2] 83 87 [2] 8f 8d [2] 98 86 [2] 83 c8 [2] be }

  condition:
    any of them
}