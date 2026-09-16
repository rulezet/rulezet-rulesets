rule TTP_XOR_MULT_DOSStub_2d16 {
  strings:
    $key_2d16 = { 79 7e [2] 0d 66 [2] 4a 64 [2] 0d 75 [2] 43 79 [2] 4f 73 [2] 58 78 [2] 43 36 [2] 7e }

  condition:
    any of them
}