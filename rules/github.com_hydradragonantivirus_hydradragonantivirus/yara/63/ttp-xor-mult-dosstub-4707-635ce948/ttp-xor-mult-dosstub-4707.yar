rule TTP_XOR_MULT_DOSStub_4707 {
  strings:
    $key_4707 = { 13 6f [2] 67 77 [2] 20 75 [2] 67 64 [2] 29 68 [2] 25 62 [2] 32 69 [2] 29 27 [2] 14 }

  condition:
    any of them
}