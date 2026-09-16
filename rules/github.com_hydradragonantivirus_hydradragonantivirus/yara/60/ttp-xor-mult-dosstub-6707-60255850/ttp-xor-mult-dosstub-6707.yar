rule TTP_XOR_MULT_DOSStub_6707 {
  strings:
    $key_6707 = { 33 6f [2] 47 77 [2] 00 75 [2] 47 64 [2] 09 68 [2] 05 62 [2] 12 69 [2] 09 27 [2] 34 }

  condition:
    any of them
}