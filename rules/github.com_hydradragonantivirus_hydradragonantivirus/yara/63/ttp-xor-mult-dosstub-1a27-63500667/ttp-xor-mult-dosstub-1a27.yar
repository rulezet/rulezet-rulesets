rule TTP_XOR_MULT_DOSStub_1a27 {
  strings:
    $key_1a27 = { 4e 4f [2] 3a 57 [2] 7d 55 [2] 3a 44 [2] 74 48 [2] 78 42 [2] 6f 49 [2] 74 07 [2] 49 }

  condition:
    any of them
}