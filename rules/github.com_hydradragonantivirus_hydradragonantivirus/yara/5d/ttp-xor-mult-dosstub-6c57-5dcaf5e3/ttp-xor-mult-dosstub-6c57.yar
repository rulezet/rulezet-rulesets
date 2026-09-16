rule TTP_XOR_MULT_DOSStub_6c57 {
  strings:
    $key_6c57 = { 38 3f [2] 4c 27 [2] 0b 25 [2] 4c 34 [2] 02 38 [2] 0e 32 [2] 19 39 [2] 02 77 [2] 3f }

  condition:
    any of them
}