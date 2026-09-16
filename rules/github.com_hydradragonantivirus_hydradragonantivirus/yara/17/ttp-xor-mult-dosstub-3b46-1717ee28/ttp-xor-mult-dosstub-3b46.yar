rule TTP_XOR_MULT_DOSStub_3b46 {
  strings:
    $key_3b46 = { 6f 2e [2] 1b 36 [2] 5c 34 [2] 1b 25 [2] 55 29 [2] 59 23 [2] 4e 28 [2] 55 66 [2] 68 }

  condition:
    any of them
}