rule TTP_XOR_MULT_DOSStub_1771 {
  strings:
    $key_1771 = { 43 19 [2] 37 01 [2] 70 03 [2] 37 12 [2] 79 1e [2] 75 14 [2] 62 1f [2] 79 51 [2] 44 }

  condition:
    any of them
}