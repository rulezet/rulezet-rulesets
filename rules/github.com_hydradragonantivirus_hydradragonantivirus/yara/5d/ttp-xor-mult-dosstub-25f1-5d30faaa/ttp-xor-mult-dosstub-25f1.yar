rule TTP_XOR_MULT_DOSStub_25f1 {
  strings:
    $key_25f1 = { 71 99 [2] 05 81 [2] 42 83 [2] 05 92 [2] 4b 9e [2] 47 94 [2] 50 9f [2] 4b d1 [2] 76 }

  condition:
    any of them
}