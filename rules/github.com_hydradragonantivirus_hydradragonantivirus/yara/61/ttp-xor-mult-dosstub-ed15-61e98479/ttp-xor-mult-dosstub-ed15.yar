rule TTP_XOR_MULT_DOSStub_ed15 {
  strings:
    $key_ed15 = { b9 7d [2] cd 65 [2] 8a 67 [2] cd 76 [2] 83 7a [2] 8f 70 [2] 98 7b [2] 83 35 [2] be }

  condition:
    any of them
}