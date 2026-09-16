rule TTP_XOR_MULT_DOSStub_37f1 {
  strings:
    $key_37f1 = { 63 99 [2] 17 81 [2] 50 83 [2] 17 92 [2] 59 9e [2] 55 94 [2] 42 9f [2] 59 d1 [2] 64 }

  condition:
    any of them
}