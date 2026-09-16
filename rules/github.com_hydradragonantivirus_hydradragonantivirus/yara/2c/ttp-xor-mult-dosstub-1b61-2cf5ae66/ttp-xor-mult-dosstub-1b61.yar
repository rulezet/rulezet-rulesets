rule TTP_XOR_MULT_DOSStub_1b61 {
  strings:
    $key_1b61 = { 4f 09 [2] 3b 11 [2] 7c 13 [2] 3b 02 [2] 75 0e [2] 79 04 [2] 6e 0f [2] 75 41 [2] 48 }

  condition:
    any of them
}