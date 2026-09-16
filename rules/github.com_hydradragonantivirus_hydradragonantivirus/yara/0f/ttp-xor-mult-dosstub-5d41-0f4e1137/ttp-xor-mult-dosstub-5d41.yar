rule TTP_XOR_MULT_DOSStub_5d41 {
  strings:
    $key_5d41 = { 09 29 [2] 7d 31 [2] 3a 33 [2] 7d 22 [2] 33 2e [2] 3f 24 [2] 28 2f [2] 33 61 [2] 0e }

  condition:
    any of them
}