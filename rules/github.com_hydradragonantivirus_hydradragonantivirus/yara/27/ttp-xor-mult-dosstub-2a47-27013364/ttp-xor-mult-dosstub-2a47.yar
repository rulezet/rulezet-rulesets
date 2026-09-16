rule TTP_XOR_MULT_DOSStub_2a47 {
  strings:
    $key_2a47 = { 7e 2f [2] 0a 37 [2] 4d 35 [2] 0a 24 [2] 44 28 [2] 48 22 [2] 5f 29 [2] 44 67 [2] 79 }

  condition:
    any of them
}