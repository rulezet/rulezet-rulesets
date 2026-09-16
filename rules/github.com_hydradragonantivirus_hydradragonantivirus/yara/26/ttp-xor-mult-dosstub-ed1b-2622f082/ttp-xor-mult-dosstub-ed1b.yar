rule TTP_XOR_MULT_DOSStub_ed1b {
  strings:
    $key_ed1b = { b9 73 [2] cd 6b [2] 8a 69 [2] cd 78 [2] 83 74 [2] 8f 7e [2] 98 75 [2] 83 3b [2] be }

  condition:
    any of them
}