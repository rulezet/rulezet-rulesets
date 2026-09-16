rule TTP_XOR_MULT_DOSStub_ed56 {
  strings:
    $key_ed56 = { b9 3e [2] cd 26 [2] 8a 24 [2] cd 35 [2] 83 39 [2] 8f 33 [2] 98 38 [2] 83 76 [2] be }

  condition:
    any of them
}