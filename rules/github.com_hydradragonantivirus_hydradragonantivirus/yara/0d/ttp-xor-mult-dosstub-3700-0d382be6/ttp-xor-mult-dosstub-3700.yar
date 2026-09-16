rule TTP_XOR_MULT_DOSStub_3700 {
  strings:
    $key_3700 = { 63 68 [2] 17 70 [2] 50 72 [2] 17 63 [2] 59 6f [2] 55 65 [2] 42 6e [2] 59 20 [2] 64 }

  condition:
    any of them
}