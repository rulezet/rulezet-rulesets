rule TTP_XOR_MULT_DOSStub_2a41 {
  strings:
    $key_2a41 = { 7e 29 [2] 0a 31 [2] 4d 33 [2] 0a 22 [2] 44 2e [2] 48 24 [2] 5f 2f [2] 44 61 [2] 79 }

  condition:
    any of them
}