rule TTP_XOR_MULT_DOSStub_ede0 {
  strings:
    $key_ede0 = { b9 88 [2] cd 90 [2] 8a 92 [2] cd 83 [2] 83 8f [2] 8f 85 [2] 98 8e [2] 83 c0 [2] be }

  condition:
    any of them
}