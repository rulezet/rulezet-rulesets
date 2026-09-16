rule TTP_XOR_MULT_DOSStub_4b37 {
  strings:
    $key_4b37 = { 1f 5f [2] 6b 47 [2] 2c 45 [2] 6b 54 [2] 25 58 [2] 29 52 [2] 3e 59 [2] 25 17 [2] 18 }

  condition:
    any of them
}