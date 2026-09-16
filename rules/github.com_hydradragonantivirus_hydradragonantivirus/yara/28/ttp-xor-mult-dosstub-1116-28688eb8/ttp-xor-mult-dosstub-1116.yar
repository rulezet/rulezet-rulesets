rule TTP_XOR_MULT_DOSStub_1116 {
  strings:
    $key_1116 = { 45 7e [2] 31 66 [2] 76 64 [2] 31 75 [2] 7f 79 [2] 73 73 [2] 64 78 [2] 7f 36 [2] 42 }

  condition:
    any of them
}