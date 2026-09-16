rule TTP_XOR_MULT_DOSStub_4b47 {
  strings:
    $key_4b47 = { 1f 2f [2] 6b 37 [2] 2c 35 [2] 6b 24 [2] 25 28 [2] 29 22 [2] 3e 29 [2] 25 67 [2] 18 }

  condition:
    any of them
}