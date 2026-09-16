rule TTP_XOR_MULT_DOSStub_ed02 {
  strings:
    $key_ed02 = { b9 6a [2] cd 72 [2] 8a 70 [2] cd 61 [2] 83 6d [2] 8f 67 [2] 98 6c [2] 83 22 [2] be }

  condition:
    any of them
}