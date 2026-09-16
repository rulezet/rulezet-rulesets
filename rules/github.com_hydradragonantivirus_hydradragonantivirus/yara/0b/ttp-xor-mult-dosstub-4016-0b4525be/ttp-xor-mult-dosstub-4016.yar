rule TTP_XOR_MULT_DOSStub_4016 {
  strings:
    $key_4016 = { 14 7e [2] 60 66 [2] 27 64 [2] 60 75 [2] 2e 79 [2] 22 73 [2] 35 78 [2] 2e 36 [2] 13 }

  condition:
    any of them
}