rule TTP_XOR_MULT_DOSStub_1960 {
  strings:
    $key_1960 = { 4d 08 [2] 39 10 [2] 7e 12 [2] 39 03 [2] 77 0f [2] 7b 05 [2] 6c 0e [2] 77 40 [2] 4a }

  condition:
    any of them
}