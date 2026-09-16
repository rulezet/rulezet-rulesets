rule TTP_XOR_MULT_DOSStub_6507 {
  strings:
    $key_6507 = { 31 6f [2] 45 77 [2] 02 75 [2] 45 64 [2] 0b 68 [2] 07 62 [2] 10 69 [2] 0b 27 [2] 36 }

  condition:
    any of them
}