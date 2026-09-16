rule TTP_XOR_MULT_DOSStub_6437 {
  strings:
    $key_6437 = { 30 5f [2] 44 47 [2] 03 45 [2] 44 54 [2] 0a 58 [2] 06 52 [2] 11 59 [2] 0a 17 [2] 37 }

  condition:
    any of them
}