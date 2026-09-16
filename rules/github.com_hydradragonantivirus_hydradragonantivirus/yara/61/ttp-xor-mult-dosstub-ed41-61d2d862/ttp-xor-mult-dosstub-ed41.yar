rule TTP_XOR_MULT_DOSStub_ed41 {
  strings:
    $key_ed41 = { b9 29 [2] cd 31 [2] 8a 33 [2] cd 22 [2] 83 2e [2] 8f 24 [2] 98 2f [2] 83 61 [2] be }

  condition:
    any of them
}