rule TTP_XOR_MULT_DOSStub_6c77 {
  strings:
    $key_6c77 = { 38 1f [2] 4c 07 [2] 0b 05 [2] 4c 14 [2] 02 18 [2] 0e 12 [2] 19 19 [2] 02 57 [2] 3f }

  condition:
    any of them
}