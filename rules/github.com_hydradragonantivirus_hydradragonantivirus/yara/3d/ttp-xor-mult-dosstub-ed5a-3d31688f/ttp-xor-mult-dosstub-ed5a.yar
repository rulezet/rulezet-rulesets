rule TTP_XOR_MULT_DOSStub_ed5a {
  strings:
    $key_ed5a = { b9 32 [2] cd 2a [2] 8a 28 [2] cd 39 [2] 83 35 [2] 8f 3f [2] 98 34 [2] 83 7a [2] be }

  condition:
    any of them
}