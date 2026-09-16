rule TTP_XOR_MULT_DOSStub_2a37 {
  strings:
    $key_2a37 = { 7e 5f [2] 0a 47 [2] 4d 45 [2] 0a 54 [2] 44 58 [2] 48 52 [2] 5f 59 [2] 44 17 [2] 79 }

  condition:
    any of them
}