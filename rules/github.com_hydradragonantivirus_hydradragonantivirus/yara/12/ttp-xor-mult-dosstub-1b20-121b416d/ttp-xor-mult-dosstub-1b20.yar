rule TTP_XOR_MULT_DOSStub_1b20 {
  strings:
    $key_1b20 = { 4f 48 [2] 3b 50 [2] 7c 52 [2] 3b 43 [2] 75 4f [2] 79 45 [2] 6e 4e [2] 75 00 [2] 48 }

  condition:
    any of them
}