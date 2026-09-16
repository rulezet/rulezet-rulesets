rule TTP_XOR_MULT_DOSStub_1a7c {
  strings:
    $key_1a7c = { 4e 14 [2] 3a 0c [2] 7d 0e [2] 3a 1f [2] 74 13 [2] 78 19 [2] 6f 12 [2] 74 5c [2] 49 }

  condition:
    any of them
}