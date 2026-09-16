rule TTP_XOR_MULT_DOSStub_2a27 {
  strings:
    $key_2a27 = { 7e 4f [2] 0a 57 [2] 4d 55 [2] 0a 44 [2] 44 48 [2] 48 42 [2] 5f 49 [2] 44 07 [2] 79 }

  condition:
    any of them
}