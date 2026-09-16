rule TTP_XOR_MULT_DOSStub_ed4a {
  strings:
    $key_ed4a = { b9 22 [2] cd 3a [2] 8a 38 [2] cd 29 [2] 83 25 [2] 8f 2f [2] 98 24 [2] 83 6a [2] be }

  condition:
    any of them
}