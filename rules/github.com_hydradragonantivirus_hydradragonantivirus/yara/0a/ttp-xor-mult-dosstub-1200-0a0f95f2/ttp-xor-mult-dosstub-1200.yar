rule TTP_XOR_MULT_DOSStub_1200 {
  strings:
    $key_1200 = { 46 68 [2] 32 70 [2] 75 72 [2] 32 63 [2] 7c 6f [2] 70 65 [2] 67 6e [2] 7c 20 [2] 41 }

  condition:
    any of them
}