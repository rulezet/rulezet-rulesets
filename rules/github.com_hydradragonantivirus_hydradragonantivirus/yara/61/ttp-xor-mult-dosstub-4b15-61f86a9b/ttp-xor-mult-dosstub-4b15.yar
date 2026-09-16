rule TTP_XOR_MULT_DOSStub_4b15 {
  strings:
    $key_4b15 = { 1f 7d [2] 6b 65 [2] 2c 67 [2] 6b 76 [2] 25 7a [2] 29 70 [2] 3e 7b [2] 25 35 [2] 18 }

  condition:
    any of them
}