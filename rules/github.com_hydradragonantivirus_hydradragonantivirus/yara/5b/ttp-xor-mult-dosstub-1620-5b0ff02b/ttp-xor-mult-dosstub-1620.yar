rule TTP_XOR_MULT_DOSStub_1620 {
  strings:
    $key_1620 = { 42 48 [2] 36 50 [2] 71 52 [2] 36 43 [2] 78 4f [2] 74 45 [2] 63 4e [2] 78 00 [2] 45 }

  condition:
    any of them
}