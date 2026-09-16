rule TTP_XOR_MULT_DOSStub_5b46 {
  strings:
    $key_5b46 = { 0f 2e [2] 7b 36 [2] 3c 34 [2] 7b 25 [2] 35 29 [2] 39 23 [2] 2e 28 [2] 35 66 [2] 08 }

  condition:
    any of them
}