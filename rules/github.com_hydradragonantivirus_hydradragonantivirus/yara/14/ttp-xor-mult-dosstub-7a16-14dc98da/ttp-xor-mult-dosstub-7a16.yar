rule TTP_XOR_MULT_DOSStub_7a16 {
  strings:
    $key_7a16 = { 2e 7e [2] 5a 66 [2] 1d 64 [2] 5a 75 [2] 14 79 [2] 18 73 [2] 0f 78 [2] 14 36 [2] 29 }

  condition:
    any of them
}