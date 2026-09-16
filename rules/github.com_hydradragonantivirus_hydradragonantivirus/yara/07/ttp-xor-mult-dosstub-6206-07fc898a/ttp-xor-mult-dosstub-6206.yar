rule TTP_XOR_MULT_DOSStub_6206 {
  strings:
    $key_6206 = { 36 6e [2] 42 76 [2] 05 74 [2] 42 65 [2] 0c 69 [2] 00 63 [2] 17 68 [2] 0c 26 [2] 31 }

  condition:
    any of them
}