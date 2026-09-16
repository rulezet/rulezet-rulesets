rule TTP_XOR_MULT_DOSStub_5761 {
  strings:
    $key_5761 = { 03 09 [2] 77 11 [2] 30 13 [2] 77 02 [2] 39 0e [2] 35 04 [2] 22 0f [2] 39 41 [2] 04 }

  condition:
    any of them
}