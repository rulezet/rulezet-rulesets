rule TTP_XOR_MULT_DOSStub_4b26 {
  strings:
    $key_4b26 = { 1f 4e [2] 6b 56 [2] 2c 54 [2] 6b 45 [2] 25 49 [2] 29 43 [2] 3e 48 [2] 25 06 [2] 18 }

  condition:
    any of them
}