rule TTP_XOR_MULT_DOSStub_6141 {
  strings:
    $key_6141 = { 35 29 [2] 41 31 [2] 06 33 [2] 41 22 [2] 0f 2e [2] 03 24 [2] 14 2f [2] 0f 61 [2] 32 }

  condition:
    any of them
}