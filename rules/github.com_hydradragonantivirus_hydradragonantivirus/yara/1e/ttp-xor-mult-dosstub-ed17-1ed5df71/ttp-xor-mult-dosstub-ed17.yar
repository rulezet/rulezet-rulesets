rule TTP_XOR_MULT_DOSStub_ed17 {
  strings:
    $key_ed17 = { b9 7f [2] cd 67 [2] 8a 65 [2] cd 74 [2] 83 78 [2] 8f 72 [2] 98 79 [2] 83 37 [2] be }

  condition:
    any of them
}