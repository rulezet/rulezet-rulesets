rule TTP_XOR_MULT_DOSStub_6417 {
  strings:
    $key_6417 = { 30 7f [2] 44 67 [2] 03 65 [2] 44 74 [2] 0a 78 [2] 06 72 [2] 11 79 [2] 0a 37 [2] 37 }

  condition:
    any of them
}