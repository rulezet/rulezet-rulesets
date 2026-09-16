rule TTP_XOR_MULT_DOSStub_4b51 {
  strings:
    $key_4b51 = { 1f 39 [2] 6b 21 [2] 2c 23 [2] 6b 32 [2] 25 3e [2] 29 34 [2] 3e 3f [2] 25 71 [2] 18 }

  condition:
    any of them
}