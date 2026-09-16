rule TTP_XOR_MULT_DOSStub_ed10 {
  strings:
    $key_ed10 = { b9 78 [2] cd 60 [2] 8a 62 [2] cd 73 [2] 83 7f [2] 8f 75 [2] 98 7e [2] 83 30 [2] be }

  condition:
    any of them
}