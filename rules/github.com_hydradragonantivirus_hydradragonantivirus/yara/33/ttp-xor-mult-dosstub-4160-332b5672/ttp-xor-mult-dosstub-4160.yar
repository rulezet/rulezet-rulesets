rule TTP_XOR_MULT_DOSStub_4160 {
  strings:
    $key_4160 = { 15 08 [2] 61 10 [2] 26 12 [2] 61 03 [2] 2f 0f [2] 23 05 [2] 34 0e [2] 2f 40 [2] 12 }

  condition:
    any of them
}