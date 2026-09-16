rule TTP_XOR_MULT_DOSStub_1b26 {
  strings:
    $key_1b26 = { 4f 4e [2] 3b 56 [2] 7c 54 [2] 3b 45 [2] 75 49 [2] 79 43 [2] 6e 48 [2] 75 06 [2] 48 }

  condition:
    any of them
}