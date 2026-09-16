rule TTP_XOR_MULT_DOSStub_1af0 {
  strings:
    $key_1af0 = { 4e 98 [2] 3a 80 [2] 7d 82 [2] 3a 93 [2] 74 9f [2] 78 95 [2] 6f 9e [2] 74 d0 [2] 49 }

  condition:
    any of them
}