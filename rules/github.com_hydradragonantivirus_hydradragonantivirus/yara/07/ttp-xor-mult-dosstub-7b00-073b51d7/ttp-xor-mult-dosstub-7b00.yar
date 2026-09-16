rule TTP_XOR_MULT_DOSStub_7b00 {
  strings:
    $key_7b00 = { 2f 68 [2] 5b 70 [2] 1c 72 [2] 5b 63 [2] 15 6f [2] 19 65 [2] 0e 6e [2] 15 20 [2] 28 }

  condition:
    any of them
}