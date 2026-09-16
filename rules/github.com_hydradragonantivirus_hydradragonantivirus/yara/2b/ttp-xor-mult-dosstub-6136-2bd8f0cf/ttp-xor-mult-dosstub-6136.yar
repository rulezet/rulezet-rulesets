rule TTP_XOR_MULT_DOSStub_6136 {
  strings:
    $key_6136 = { 35 5e [2] 41 46 [2] 06 44 [2] 41 55 [2] 0f 59 [2] 03 53 [2] 14 58 [2] 0f 16 [2] 32 }

  condition:
    any of them
}