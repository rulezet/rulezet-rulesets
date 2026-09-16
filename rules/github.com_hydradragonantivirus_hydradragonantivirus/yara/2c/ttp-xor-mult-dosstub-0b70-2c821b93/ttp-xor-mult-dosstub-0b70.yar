rule TTP_XOR_MULT_DOSStub_0b70 {
  strings:
    $key_0b70 = { 5f 18 [2] 2b 00 [2] 6c 02 [2] 2b 13 [2] 65 1f [2] 69 15 [2] 7e 1e [2] 65 50 [2] 58 }

  condition:
    any of them
}