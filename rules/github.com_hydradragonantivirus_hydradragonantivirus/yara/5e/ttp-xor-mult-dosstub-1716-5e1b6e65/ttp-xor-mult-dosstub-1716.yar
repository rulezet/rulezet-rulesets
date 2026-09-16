rule TTP_XOR_MULT_DOSStub_1716 {
  strings:
    $key_1716 = { 43 7e [2] 37 66 [2] 70 64 [2] 37 75 [2] 79 79 [2] 75 73 [2] 62 78 [2] 79 36 [2] 44 }

  condition:
    any of them
}