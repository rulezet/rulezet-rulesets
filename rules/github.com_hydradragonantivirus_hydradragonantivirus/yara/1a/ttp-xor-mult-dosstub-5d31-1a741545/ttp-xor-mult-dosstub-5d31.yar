rule TTP_XOR_MULT_DOSStub_5d31 {
  strings:
    $key_5d31 = { 09 59 [2] 7d 41 [2] 3a 43 [2] 7d 52 [2] 33 5e [2] 3f 54 [2] 28 5f [2] 33 11 [2] 0e }

  condition:
    any of them
}