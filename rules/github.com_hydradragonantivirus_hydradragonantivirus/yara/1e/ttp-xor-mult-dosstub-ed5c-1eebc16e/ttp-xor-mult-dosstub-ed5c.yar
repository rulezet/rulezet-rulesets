rule TTP_XOR_MULT_DOSStub_ed5c {
  strings:
    $key_ed5c = { b9 34 [2] cd 2c [2] 8a 2e [2] cd 3f [2] 83 33 [2] 8f 39 [2] 98 32 [2] 83 7c [2] be }

  condition:
    any of them
}