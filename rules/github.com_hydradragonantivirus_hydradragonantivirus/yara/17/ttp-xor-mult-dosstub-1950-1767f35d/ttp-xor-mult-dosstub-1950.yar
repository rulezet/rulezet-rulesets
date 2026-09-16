rule TTP_XOR_MULT_DOSStub_1950 {
  strings:
    $key_1950 = { 4d 38 [2] 39 20 [2] 7e 22 [2] 39 33 [2] 77 3f [2] 7b 35 [2] 6c 3e [2] 77 70 [2] 4a }

  condition:
    any of them
}