rule TTP_XOR_MULT_DOSStub_1b40 {
  strings:
    $key_1b40 = { 4f 28 [2] 3b 30 [2] 7c 32 [2] 3b 23 [2] 75 2f [2] 79 25 [2] 6e 2e [2] 75 60 [2] 48 }

  condition:
    any of them
}