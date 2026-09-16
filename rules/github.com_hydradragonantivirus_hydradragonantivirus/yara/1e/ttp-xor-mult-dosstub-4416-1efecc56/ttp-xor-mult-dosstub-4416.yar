rule TTP_XOR_MULT_DOSStub_4416 {
  strings:
    $key_4416 = { 10 7e [2] 64 66 [2] 23 64 [2] 64 75 [2] 2a 79 [2] 26 73 [2] 31 78 [2] 2a 36 [2] 17 }

  condition:
    any of them
}