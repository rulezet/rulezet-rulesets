rule TTP_XOR_MULT_DOSStub_1906 {
  strings:
    $key_1906 = { 4d 6e [2] 39 76 [2] 7e 74 [2] 39 65 [2] 77 69 [2] 7b 63 [2] 6c 68 [2] 77 26 [2] 4a }

  condition:
    any of them
}