rule TTP_XOR_MULT_DOSStub_6c07 {
  strings:
    $key_6c07 = { 38 6f [2] 4c 77 [2] 0b 75 [2] 4c 64 [2] 02 68 [2] 0e 62 [2] 19 69 [2] 02 27 [2] 3f }

  condition:
    any of them
}