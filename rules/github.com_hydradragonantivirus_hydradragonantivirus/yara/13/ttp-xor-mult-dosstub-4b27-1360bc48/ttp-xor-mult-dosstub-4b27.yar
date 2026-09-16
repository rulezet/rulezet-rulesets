rule TTP_XOR_MULT_DOSStub_4b27 {
  strings:
    $key_4b27 = { 1f 4f [2] 6b 57 [2] 2c 55 [2] 6b 44 [2] 25 48 [2] 29 42 [2] 3e 49 [2] 25 07 [2] 18 }

  condition:
    any of them
}