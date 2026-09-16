rule TTP_XOR_MULT_DOSStub_2a40 {
  strings:
    $key_2a40 = { 7e 28 [2] 0a 30 [2] 4d 32 [2] 0a 23 [2] 44 2f [2] 48 25 [2] 5f 2e [2] 44 60 [2] 79 }

  condition:
    any of them
}