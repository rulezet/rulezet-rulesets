rule TTP_XOR_MULT_DOSStub_6421 {
  strings:
    $key_6421 = { 30 49 [2] 44 51 [2] 03 53 [2] 44 42 [2] 0a 4e [2] 06 44 [2] 11 4f [2] 0a 01 [2] 37 }

  condition:
    any of them
}