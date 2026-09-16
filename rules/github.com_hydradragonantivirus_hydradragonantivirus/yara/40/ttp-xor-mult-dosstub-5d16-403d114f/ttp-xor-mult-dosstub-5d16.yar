rule TTP_XOR_MULT_DOSStub_5d16 {
  strings:
    $key_5d16 = { 09 7e [2] 7d 66 [2] 3a 64 [2] 7d 75 [2] 33 79 [2] 3f 73 [2] 28 78 [2] 33 36 [2] 0e }

  condition:
    any of them
}