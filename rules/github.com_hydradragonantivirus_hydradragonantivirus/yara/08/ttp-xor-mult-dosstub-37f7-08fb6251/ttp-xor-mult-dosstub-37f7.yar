rule TTP_XOR_MULT_DOSStub_37f7 {
  strings:
    $key_37f7 = { 63 9f [2] 17 87 [2] 50 85 [2] 17 94 [2] 59 98 [2] 55 92 [2] 42 99 [2] 59 d7 [2] 64 }

  condition:
    any of them
}