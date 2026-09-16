rule TTP_XOR_MULT_DOSStub_6426 {
  strings:
    $key_6426 = { 30 4e [2] 44 56 [2] 03 54 [2] 44 45 [2] 0a 49 [2] 06 43 [2] 11 48 [2] 0a 06 [2] 37 }

  condition:
    any of them
}