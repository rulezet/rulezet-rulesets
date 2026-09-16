rule TTP_XOR_MULT_DOSStub_74f7 {
  strings:
    $key_74f7 = { 20 9f [2] 54 87 [2] 13 85 [2] 54 94 [2] 1a 98 [2] 16 92 [2] 01 99 [2] 1a d7 [2] 27 }

  condition:
    any of them
}