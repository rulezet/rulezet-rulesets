rule TTP_XOR_MULT_DOSStub_1a60 {
  strings:
    $key_1a60 = { 4e 08 [2] 3a 10 [2] 7d 12 [2] 3a 03 [2] 74 0f [2] 78 05 [2] 6f 0e [2] 74 40 [2] 49 }

  condition:
    any of them
}