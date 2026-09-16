rule TTP_XOR_MULT_DOSStub_4b00 {
  strings:
    $key_4b00 = { 1f 68 [2] 6b 70 [2] 2c 72 [2] 6b 63 [2] 25 6f [2] 29 65 [2] 3e 6e [2] 25 20 [2] 18 }

  condition:
    any of them
}