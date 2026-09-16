rule TTP_XOR_MULT_DOSStub_6131 {
  strings:
    $key_6131 = { 35 59 [2] 41 41 [2] 06 43 [2] 41 52 [2] 0f 5e [2] 03 54 [2] 14 5f [2] 0f 11 [2] 32 }

  condition:
    any of them
}