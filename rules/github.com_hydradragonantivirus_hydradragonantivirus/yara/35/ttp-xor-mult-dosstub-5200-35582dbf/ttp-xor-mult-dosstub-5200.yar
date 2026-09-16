rule TTP_XOR_MULT_DOSStub_5200 {
  strings:
    $key_5200 = { 06 68 [2] 72 70 [2] 35 72 [2] 72 63 [2] 3c 6f [2] 30 65 [2] 27 6e [2] 3c 20 [2] 01 }

  condition:
    any of them
}