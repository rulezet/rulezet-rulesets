rule TTP_XOR_MULT_DOSStub_1b60 {
  strings:
    $key_1b60 = { 4f 08 [2] 3b 10 [2] 7c 12 [2] 3b 03 [2] 75 0f [2] 79 05 [2] 6e 0e [2] 75 40 [2] 48 }

  condition:
    any of them
}