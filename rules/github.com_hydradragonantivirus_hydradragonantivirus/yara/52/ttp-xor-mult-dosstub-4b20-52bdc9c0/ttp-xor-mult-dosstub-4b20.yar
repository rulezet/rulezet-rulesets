rule TTP_XOR_MULT_DOSStub_4b20 {
  strings:
    $key_4b20 = { 1f 48 [2] 6b 50 [2] 2c 52 [2] 6b 43 [2] 25 4f [2] 29 45 [2] 3e 4e [2] 25 00 [2] 18 }

  condition:
    any of them
}