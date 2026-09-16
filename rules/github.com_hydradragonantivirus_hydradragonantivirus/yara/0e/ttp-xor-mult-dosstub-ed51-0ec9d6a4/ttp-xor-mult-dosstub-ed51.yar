rule TTP_XOR_MULT_DOSStub_ed51 {
  strings:
    $key_ed51 = { b9 39 [2] cd 21 [2] 8a 23 [2] cd 32 [2] 83 3e [2] 8f 34 [2] 98 3f [2] 83 71 [2] be }

  condition:
    any of them
}