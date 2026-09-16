rule TTP_XOR_MULT_DOSStub_1a47 {
  strings:
    $key_1a47 = { 4e 2f [2] 3a 37 [2] 7d 35 [2] 3a 24 [2] 74 28 [2] 78 22 [2] 6f 29 [2] 74 67 [2] 49 }

  condition:
    any of them
}