rule TTP_XOR_MULT_DOSStub_1b00 {
  strings:
    $key_1b00 = { 4f 68 [2] 3b 70 [2] 7c 72 [2] 3b 63 [2] 75 6f [2] 79 65 [2] 6e 6e [2] 75 20 [2] 48 }

  condition:
    any of them
}