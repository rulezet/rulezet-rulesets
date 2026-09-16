rule TTP_XOR_MULT_DOSStub_ed40 {
  strings:
    $key_ed40 = { b9 28 [2] cd 30 [2] 8a 32 [2] cd 23 [2] 83 2f [2] 8f 25 [2] 98 2e [2] 83 60 [2] be }

  condition:
    any of them
}