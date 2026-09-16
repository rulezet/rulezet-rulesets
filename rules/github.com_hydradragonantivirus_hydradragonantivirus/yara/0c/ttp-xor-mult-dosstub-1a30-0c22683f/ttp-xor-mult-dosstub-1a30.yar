rule TTP_XOR_MULT_DOSStub_1a30 {
  strings:
    $key_1a30 = { 4e 58 [2] 3a 40 [2] 7d 42 [2] 3a 53 [2] 74 5f [2] 78 55 [2] 6f 5e [2] 74 10 [2] 49 }

  condition:
    any of them
}