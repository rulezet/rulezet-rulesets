rule TTP_XOR_MULT_DOSStub_1141 {
  strings:
    $key_1141 = { 45 29 [2] 31 31 [2] 76 33 [2] 31 22 [2] 7f 2e [2] 73 24 [2] 64 2f [2] 7f 61 [2] 42 }

  condition:
    any of them
}