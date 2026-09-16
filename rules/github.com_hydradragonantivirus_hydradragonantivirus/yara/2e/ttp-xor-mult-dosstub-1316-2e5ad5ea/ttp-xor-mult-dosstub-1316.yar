rule TTP_XOR_MULT_DOSStub_1316 {
  strings:
    $key_1316 = { 47 7e [2] 33 66 [2] 74 64 [2] 33 75 [2] 7d 79 [2] 71 73 [2] 66 78 [2] 7d 36 [2] 40 }

  condition:
    any of them
}