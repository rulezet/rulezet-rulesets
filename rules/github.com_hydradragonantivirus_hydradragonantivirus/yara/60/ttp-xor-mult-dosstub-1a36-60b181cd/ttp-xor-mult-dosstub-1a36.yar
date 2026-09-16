rule TTP_XOR_MULT_DOSStub_1a36 {
  strings:
    $key_1a36 = { 4e 5e [2] 3a 46 [2] 7d 44 [2] 3a 55 [2] 74 59 [2] 78 53 [2] 6f 58 [2] 74 16 [2] 49 }

  condition:
    any of them
}