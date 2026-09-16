rule TTP_XOR_MULT_DOSStub_6240 {
  strings:
    $key_6240 = { 36 28 [2] 42 30 [2] 05 32 [2] 42 23 [2] 0c 2f [2] 00 25 [2] 17 2e [2] 0c 60 [2] 31 }

  condition:
    any of them
}