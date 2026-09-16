rule TTP_XOR_MULT_DOSStub_5160 {
  strings:
    $key_5160 = { 05 08 [2] 71 10 [2] 36 12 [2] 71 03 [2] 3f 0f [2] 33 05 [2] 24 0e [2] 3f 40 [2] 02 }

  condition:
    any of them
}