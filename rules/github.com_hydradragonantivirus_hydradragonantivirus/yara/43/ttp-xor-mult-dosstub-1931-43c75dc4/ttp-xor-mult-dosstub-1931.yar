rule TTP_XOR_MULT_DOSStub_1931 {
  strings:
    $key_1931 = { 4d 59 [2] 39 41 [2] 7e 43 [2] 39 52 [2] 77 5e [2] 7b 54 [2] 6c 5f [2] 77 11 [2] 4a }

  condition:
    any of them
}