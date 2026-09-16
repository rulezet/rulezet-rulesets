rule TTP_XOR_MULT_DOSStub_7507 {
  strings:
    $key_7507 = { 21 6f [2] 55 77 [2] 12 75 [2] 55 64 [2] 1b 68 [2] 17 62 [2] 00 69 [2] 1b 27 [2] 26 }

  condition:
    any of them
}