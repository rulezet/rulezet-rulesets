rule TTP_XOR_MULT_DOSStub_1af6 {
  strings:
    $key_1af6 = { 4e 9e [2] 3a 86 [2] 7d 84 [2] 3a 95 [2] 74 99 [2] 78 93 [2] 6f 98 [2] 74 d6 [2] 49 }

  condition:
    any of them
}