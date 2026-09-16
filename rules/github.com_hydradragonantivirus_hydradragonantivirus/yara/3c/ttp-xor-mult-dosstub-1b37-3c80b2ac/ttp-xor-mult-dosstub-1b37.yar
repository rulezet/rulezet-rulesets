rule TTP_XOR_MULT_DOSStub_1b37 {
  strings:
    $key_1b37 = { 4f 5f [2] 3b 47 [2] 7c 45 [2] 3b 54 [2] 75 58 [2] 79 52 [2] 6e 59 [2] 75 17 [2] 48 }

  condition:
    any of them
}