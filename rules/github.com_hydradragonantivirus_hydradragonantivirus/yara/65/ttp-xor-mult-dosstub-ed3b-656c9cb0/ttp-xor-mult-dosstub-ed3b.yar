rule TTP_XOR_MULT_DOSStub_ed3b {
  strings:
    $key_ed3b = { b9 53 [2] cd 4b [2] 8a 49 [2] cd 58 [2] 83 54 [2] 8f 5e [2] 98 55 [2] 83 1b [2] be }

  condition:
    any of them
}