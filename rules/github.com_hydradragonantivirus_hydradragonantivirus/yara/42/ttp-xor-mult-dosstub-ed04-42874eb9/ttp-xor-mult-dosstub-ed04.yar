rule TTP_XOR_MULT_DOSStub_ed04 {
  strings:
    $key_ed04 = { b9 6c [2] cd 74 [2] 8a 76 [2] cd 67 [2] 83 6b [2] 8f 61 [2] 98 6a [2] 83 24 [2] be }

  condition:
    any of them
}