rule TTP_XOR_MULT_DOSStub_0160 {
  strings:
    $key_0160 = { 55 08 [2] 21 10 [2] 66 12 [2] 21 03 [2] 6f 0f [2] 63 05 [2] 74 0e [2] 6f 40 [2] 52 }

  condition:
    any of them
}