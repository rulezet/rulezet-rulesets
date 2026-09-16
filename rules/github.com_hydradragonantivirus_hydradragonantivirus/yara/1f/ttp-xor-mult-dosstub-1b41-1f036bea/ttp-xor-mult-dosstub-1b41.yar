rule TTP_XOR_MULT_DOSStub_1b41 {
  strings:
    $key_1b41 = { 4f 29 [2] 3b 31 [2] 7c 33 [2] 3b 22 [2] 75 2e [2] 79 24 [2] 6e 2f [2] 75 61 [2] 48 }

  condition:
    any of them
}