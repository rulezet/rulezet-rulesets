rule TTP_XOR_MULT_DOSStub_3a30 {
  strings:
    $key_3a30 = { 6e 58 [2] 1a 40 [2] 5d 42 [2] 1a 53 [2] 54 5f [2] 58 55 [2] 4f 5e [2] 54 10 [2] 69 }

  condition:
    any of them
}