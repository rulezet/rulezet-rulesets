rule TTP_XOR_MULT_DOSStub_edf0 {
  strings:
    $key_edf0 = { b9 98 [2] cd 80 [2] 8a 82 [2] cd 93 [2] 83 9f [2] 8f 95 [2] 98 9e [2] 83 d0 [2] be }

  condition:
    any of them
}