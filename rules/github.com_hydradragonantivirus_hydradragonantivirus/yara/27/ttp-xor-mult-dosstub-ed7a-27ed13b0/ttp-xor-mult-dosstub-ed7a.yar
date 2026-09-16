rule TTP_XOR_MULT_DOSStub_ed7a {
  strings:
    $key_ed7a = { b9 12 [2] cd 0a [2] 8a 08 [2] cd 19 [2] 83 15 [2] 8f 1f [2] 98 14 [2] 83 5a [2] be }

  condition:
    any of them
}