rule TTP_XOR_MULT_DOSStub_ed1a {
  strings:
    $key_ed1a = { b9 72 [2] cd 6a [2] 8a 68 [2] cd 79 [2] 83 75 [2] 8f 7f [2] 98 74 [2] 83 3a [2] be }

  condition:
    any of them
}