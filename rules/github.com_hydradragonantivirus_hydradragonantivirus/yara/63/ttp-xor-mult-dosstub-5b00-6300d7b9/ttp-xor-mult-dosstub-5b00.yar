rule TTP_XOR_MULT_DOSStub_5b00 {
  strings:
    $key_5b00 = { 0f 68 [2] 7b 70 [2] 3c 72 [2] 7b 63 [2] 35 6f [2] 39 65 [2] 2e 6e [2] 35 20 [2] 08 }

  condition:
    any of them
}