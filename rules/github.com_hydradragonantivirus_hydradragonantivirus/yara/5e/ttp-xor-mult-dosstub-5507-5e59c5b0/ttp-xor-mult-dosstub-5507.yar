rule TTP_XOR_MULT_DOSStub_5507 {
  strings:
    $key_5507 = { 01 6f [2] 75 77 [2] 32 75 [2] 75 64 [2] 3b 68 [2] 37 62 [2] 20 69 [2] 3b 27 [2] 06 }

  condition:
    any of them
}