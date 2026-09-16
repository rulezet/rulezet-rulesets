rule TTP_XOR_MULT_DOSStub_ed08 {
  strings:
    $key_ed08 = { b9 60 [2] cd 78 [2] 8a 7a [2] cd 6b [2] 83 67 [2] 8f 6d [2] 98 66 [2] 83 28 [2] be }

  condition:
    any of them
}