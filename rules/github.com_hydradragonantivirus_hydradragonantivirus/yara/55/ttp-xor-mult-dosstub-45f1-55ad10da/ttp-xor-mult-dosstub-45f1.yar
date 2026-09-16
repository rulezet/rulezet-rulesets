rule TTP_XOR_MULT_DOSStub_45f1 {
  strings:
    $key_45f1 = { 11 99 [2] 65 81 [2] 22 83 [2] 65 92 [2] 2b 9e [2] 27 94 [2] 30 9f [2] 2b d1 [2] 16 }

  condition:
    any of them
}