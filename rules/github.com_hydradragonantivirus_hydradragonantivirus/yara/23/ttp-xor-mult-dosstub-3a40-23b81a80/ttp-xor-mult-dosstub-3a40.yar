rule TTP_XOR_MULT_DOSStub_3a40 {
  strings:
    $key_3a40 = { 6e 28 [2] 1a 30 [2] 5d 32 [2] 1a 23 [2] 54 2f [2] 58 25 [2] 4f 2e [2] 54 60 [2] 69 }

  condition:
    any of them
}