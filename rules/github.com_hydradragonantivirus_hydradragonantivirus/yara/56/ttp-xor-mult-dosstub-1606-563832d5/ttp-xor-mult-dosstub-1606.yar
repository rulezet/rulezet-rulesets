rule TTP_XOR_MULT_DOSStub_1606 {
  strings:
    $key_1606 = { 42 6e [2] 36 76 [2] 71 74 [2] 36 65 [2] 78 69 [2] 74 63 [2] 63 68 [2] 78 26 [2] 45 }

  condition:
    any of them
}