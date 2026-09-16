rule TTP_XOR_MULT_DOSStub_1917 {
  strings:
    $key_1917 = { 4d 7f [2] 39 67 [2] 7e 65 [2] 39 74 [2] 77 78 [2] 7b 72 [2] 6c 79 [2] 77 37 [2] 4a }

  condition:
    any of them
}