rule TTP_XOR_MULT_DOSStub_1b57 {
  strings:
    $key_1b57 = { 4f 3f [2] 3b 27 [2] 7c 25 [2] 3b 34 [2] 75 38 [2] 79 32 [2] 6e 39 [2] 75 77 [2] 48 }

  condition:
    any of them
}