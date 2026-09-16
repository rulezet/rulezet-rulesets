rule TTP_XOR_MULT_DOSStub_ed4c {
  strings:
    $key_ed4c = { b9 24 [2] cd 3c [2] 8a 3e [2] cd 2f [2] 83 23 [2] 8f 29 [2] 98 22 [2] 83 6c [2] be }

  condition:
    any of them
}