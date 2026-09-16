rule TTP_XOR_MULT_DOSStub_1b51 {
  strings:
    $key_1b51 = { 4f 39 [2] 3b 21 [2] 7c 23 [2] 3b 32 [2] 75 3e [2] 79 34 [2] 6e 3f [2] 75 71 [2] 48 }

  condition:
    any of them
}