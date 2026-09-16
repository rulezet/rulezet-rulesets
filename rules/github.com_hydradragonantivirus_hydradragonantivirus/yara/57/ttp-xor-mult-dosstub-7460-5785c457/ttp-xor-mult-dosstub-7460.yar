rule TTP_XOR_MULT_DOSStub_7460 {
  strings:
    $key_7460 = { 20 08 [2] 54 10 [2] 13 12 [2] 54 03 [2] 1a 0f [2] 16 05 [2] 01 0e [2] 1a 40 [2] 27 }

  condition:
    any of them
}