rule TTP_XOR_MULT_DOSStub_1a21 {
  strings:
    $key_1a21 = { 4e 49 [2] 3a 51 [2] 7d 53 [2] 3a 42 [2] 74 4e [2] 78 44 [2] 6f 4f [2] 74 01 [2] 49 }

  condition:
    any of them
}