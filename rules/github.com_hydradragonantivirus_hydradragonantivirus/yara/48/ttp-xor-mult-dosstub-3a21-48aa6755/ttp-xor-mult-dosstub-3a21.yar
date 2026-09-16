rule TTP_XOR_MULT_DOSStub_3a21 {
  strings:
    $key_3a21 = { 6e 49 [2] 1a 51 [2] 5d 53 [2] 1a 42 [2] 54 4e [2] 58 44 [2] 4f 4f [2] 54 01 [2] 69 }

  condition:
    any of them
}