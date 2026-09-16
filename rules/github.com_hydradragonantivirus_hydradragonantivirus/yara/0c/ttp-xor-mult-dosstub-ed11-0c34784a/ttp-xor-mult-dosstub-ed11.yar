rule TTP_XOR_MULT_DOSStub_ed11 {
  strings:
    $key_ed11 = { b9 79 [2] cd 61 [2] 8a 63 [2] cd 72 [2] 83 7e [2] 8f 74 [2] 98 7f [2] 83 31 [2] be }

  condition:
    any of them
}