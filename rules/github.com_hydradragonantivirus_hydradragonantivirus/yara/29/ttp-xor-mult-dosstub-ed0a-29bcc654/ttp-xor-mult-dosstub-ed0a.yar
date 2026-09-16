rule TTP_XOR_MULT_DOSStub_ed0a {
  strings:
    $key_ed0a = { b9 62 [2] cd 7a [2] 8a 78 [2] cd 69 [2] 83 65 [2] 8f 6f [2] 98 64 [2] 83 2a [2] be }

  condition:
    any of them
}