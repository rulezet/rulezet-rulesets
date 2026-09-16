rule TTP_XOR_MULT_DOSStub_6236 {
  strings:
    $key_6236 = { 36 5e [2] 42 46 [2] 05 44 [2] 42 55 [2] 0c 59 [2] 00 53 [2] 17 58 [2] 0c 16 [2] 31 }

  condition:
    any of them
}