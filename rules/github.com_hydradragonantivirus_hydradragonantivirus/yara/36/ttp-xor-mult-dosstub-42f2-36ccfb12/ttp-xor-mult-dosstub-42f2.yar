rule TTP_XOR_MULT_DOSStub_42f2 {
  strings:
    $key_42f2 = { 16 9a [2] 62 82 [2] 25 80 [2] 62 91 [2] 2c 9d [2] 20 97 [2] 37 9c [2] 2c d2 [2] 11 }

  condition:
    any of them
}