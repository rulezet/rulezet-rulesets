rule TTP_XOR_MULT_DOSStub_4716 {
  strings:
    $key_4716 = { 13 7e [2] 67 66 [2] 20 64 [2] 67 75 [2] 29 79 [2] 25 73 [2] 32 78 [2] 29 36 [2] 14 }

  condition:
    any of them
}