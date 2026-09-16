rule TTP_XOR_MULT_DOSStub_2a17 {
  strings:
    $key_2a17 = { 7e 7f [2] 0a 67 [2] 4d 65 [2] 0a 74 [2] 44 78 [2] 48 72 [2] 5f 79 [2] 44 37 [2] 79 }

  condition:
    any of them
}