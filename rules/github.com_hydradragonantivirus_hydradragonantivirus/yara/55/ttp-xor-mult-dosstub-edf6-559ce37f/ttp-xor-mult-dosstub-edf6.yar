rule TTP_XOR_MULT_DOSStub_edf6 {
  strings:
    $key_edf6 = { b9 9e [2] cd 86 [2] 8a 84 [2] cd 95 [2] 83 99 [2] 8f 93 [2] 98 98 [2] 83 d6 [2] be }

  condition:
    any of them
}