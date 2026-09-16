rule TTP_XOR_MULT_DOSStub_1b50 {
  strings:
    $key_1b50 = { 4f 38 [2] 3b 20 [2] 7c 22 [2] 3b 33 [2] 75 3f [2] 79 35 [2] 6e 3e [2] 75 70 [2] 48 }

  condition:
    any of them
}