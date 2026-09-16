rule TTP_XOR_MULT_DOSStub_edb7 {
  strings:
    $key_edb7 = { b9 df [2] cd c7 [2] 8a c5 [2] cd d4 [2] 83 d8 [2] 8f d2 [2] 98 d9 [2] 83 97 [2] be }

  condition:
    any of them
}