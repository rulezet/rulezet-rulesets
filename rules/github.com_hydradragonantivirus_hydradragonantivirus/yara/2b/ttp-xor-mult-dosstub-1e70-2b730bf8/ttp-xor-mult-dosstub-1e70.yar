rule TTP_XOR_MULT_DOSStub_1e70 {
  strings:
    $key_1e70 = { 4a 18 [2] 3e 00 [2] 79 02 [2] 3e 13 [2] 70 1f [2] 7c 15 [2] 6b 1e [2] 70 50 [2] 4d }

  condition:
    any of them
}