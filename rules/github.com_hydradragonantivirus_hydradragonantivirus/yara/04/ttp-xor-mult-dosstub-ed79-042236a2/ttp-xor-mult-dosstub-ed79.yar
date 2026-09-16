rule TTP_XOR_MULT_DOSStub_ed79 {
  strings:
    $key_ed79 = { b9 11 [2] cd 09 [2] 8a 0b [2] cd 1a [2] 83 16 [2] 8f 1c [2] 98 17 [2] 83 59 [2] be }

  condition:
    any of them
}