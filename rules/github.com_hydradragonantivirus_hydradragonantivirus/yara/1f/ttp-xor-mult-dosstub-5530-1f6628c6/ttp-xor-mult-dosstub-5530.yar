rule TTP_XOR_MULT_DOSStub_5530 {
  strings:
    $key_5530 = { 01 58 [2] 75 40 [2] 32 42 [2] 75 53 [2] 3b 5f [2] 37 55 [2] 20 5e [2] 3b 10 [2] 06 }

  condition:
    any of them
}