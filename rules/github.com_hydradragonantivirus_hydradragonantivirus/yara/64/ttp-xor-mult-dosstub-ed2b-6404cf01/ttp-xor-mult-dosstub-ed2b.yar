rule TTP_XOR_MULT_DOSStub_ed2b {
  strings:
    $key_ed2b = { b9 43 [2] cd 5b [2] 8a 59 [2] cd 48 [2] 83 44 [2] 8f 4e [2] 98 45 [2] 83 0b [2] be }

  condition:
    any of them
}