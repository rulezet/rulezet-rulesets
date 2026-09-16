rule TTP_XOR_MULT_DOSStub_1a41 {
  strings:
    $key_1a41 = { 4e 29 [2] 3a 31 [2] 7d 33 [2] 3a 22 [2] 74 2e [2] 78 24 [2] 6f 2f [2] 74 61 [2] 49 }

  condition:
    any of them
}