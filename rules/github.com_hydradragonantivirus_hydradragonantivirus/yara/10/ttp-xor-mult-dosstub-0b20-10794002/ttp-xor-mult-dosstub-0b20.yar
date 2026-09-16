rule TTP_XOR_MULT_DOSStub_0b20 {
  strings:
    $key_0b20 = { 5f 48 [2] 2b 50 [2] 6c 52 [2] 2b 43 [2] 65 4f [2] 69 45 [2] 7e 4e [2] 65 00 [2] 58 }

  condition:
    any of them
}