rule TTP_XOR_MULT_DOSStub_7407 {
  strings:
    $key_7407 = { 20 6f [2] 54 77 [2] 13 75 [2] 54 64 [2] 1a 68 [2] 16 62 [2] 01 69 [2] 1a 27 [2] 27 }

  condition:
    any of them
}