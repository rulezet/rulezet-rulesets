rule TTP_XOR_MULT_DOSStub_2307 {
  strings:
    $key_2307 = { 77 6f [2] 03 77 [2] 44 75 [2] 03 64 [2] 4d 68 [2] 41 62 [2] 56 69 [2] 4d 27 [2] 70 }

  condition:
    any of them
}