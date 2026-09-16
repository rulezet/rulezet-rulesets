rule TTP_XOR_MULT_DOSStub_ed29 {
  strings:
    $key_ed29 = { b9 41 [2] cd 59 [2] 8a 5b [2] cd 4a [2] 83 46 [2] 8f 4c [2] 98 47 [2] 83 09 [2] be }

  condition:
    any of them
}