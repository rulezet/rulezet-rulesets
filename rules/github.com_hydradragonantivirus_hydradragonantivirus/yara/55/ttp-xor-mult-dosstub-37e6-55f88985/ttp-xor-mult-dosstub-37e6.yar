rule TTP_XOR_MULT_DOSStub_37e6 {
  strings:
    $key_37e6 = { 63 8e [2] 17 96 [2] 50 94 [2] 17 85 [2] 59 89 [2] 55 83 [2] 42 88 [2] 59 c6 [2] 64 }

  condition:
    any of them
}