rule TTP_XOR_MULT_DOSStub_6407 {
  strings:
    $key_6407 = { 30 6f [2] 44 77 [2] 03 75 [2] 44 64 [2] 0a 68 [2] 06 62 [2] 11 69 [2] 0a 27 [2] 37 }

  condition:
    any of them
}