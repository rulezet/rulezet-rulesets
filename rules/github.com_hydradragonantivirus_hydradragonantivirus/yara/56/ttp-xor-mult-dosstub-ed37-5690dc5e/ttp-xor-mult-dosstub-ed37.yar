rule TTP_XOR_MULT_DOSStub_ed37 {
  strings:
    $key_ed37 = { b9 5f [2] cd 47 [2] 8a 45 [2] cd 54 [2] 83 58 [2] 8f 52 [2] 98 59 [2] 83 17 [2] be }

  condition:
    any of them
}