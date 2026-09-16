rule TTP_XOR_MULT_DOSStub_ed5b {
  strings:
    $key_ed5b = { b9 33 [2] cd 2b [2] 8a 29 [2] cd 38 [2] 83 34 [2] 8f 3e [2] 98 35 [2] 83 7b [2] be }

  condition:
    any of them
}