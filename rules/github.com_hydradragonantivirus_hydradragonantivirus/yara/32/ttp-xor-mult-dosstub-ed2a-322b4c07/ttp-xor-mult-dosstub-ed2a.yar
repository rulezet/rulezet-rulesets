rule TTP_XOR_MULT_DOSStub_ed2a {
  strings:
    $key_ed2a = { b9 42 [2] cd 5a [2] 8a 58 [2] cd 49 [2] 83 45 [2] 8f 4f [2] 98 44 [2] 83 0a [2] be }

  condition:
    any of them
}