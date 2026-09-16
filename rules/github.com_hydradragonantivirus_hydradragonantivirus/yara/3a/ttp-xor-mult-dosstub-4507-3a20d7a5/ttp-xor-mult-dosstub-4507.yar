rule TTP_XOR_MULT_DOSStub_4507 {
  strings:
    $key_4507 = { 11 6f [2] 65 77 [2] 22 75 [2] 65 64 [2] 2b 68 [2] 27 62 [2] 30 69 [2] 2b 27 [2] 16 }

  condition:
    any of them
}