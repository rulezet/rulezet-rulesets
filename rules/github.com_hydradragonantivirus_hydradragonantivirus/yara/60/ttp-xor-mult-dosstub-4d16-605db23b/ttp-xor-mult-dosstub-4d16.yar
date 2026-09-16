rule TTP_XOR_MULT_DOSStub_4d16 {
  strings:
    $key_4d16 = { 19 7e [2] 6d 66 [2] 2a 64 [2] 6d 75 [2] 23 79 [2] 2f 73 [2] 38 78 [2] 23 36 [2] 1e }

  condition:
    any of them
}