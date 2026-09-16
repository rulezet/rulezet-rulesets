rule TTP_XOR_MULT_DOSStub_00f1 {
  strings:
    $key_00f1 = { 54 99 [2] 20 81 [2] 67 83 [2] 20 92 [2] 6e 9e [2] 62 94 [2] 75 9f [2] 6e d1 [2] 53 }

  condition:
    any of them
}