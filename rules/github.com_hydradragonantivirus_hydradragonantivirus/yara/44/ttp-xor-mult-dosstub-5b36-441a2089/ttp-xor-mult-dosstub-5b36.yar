rule TTP_XOR_MULT_DOSStub_5b36 {
  strings:
    $key_5b36 = { 0f 5e [2] 7b 46 [2] 3c 44 [2] 7b 55 [2] 35 59 [2] 39 53 [2] 2e 58 [2] 35 16 [2] 08 }

  condition:
    any of them
}