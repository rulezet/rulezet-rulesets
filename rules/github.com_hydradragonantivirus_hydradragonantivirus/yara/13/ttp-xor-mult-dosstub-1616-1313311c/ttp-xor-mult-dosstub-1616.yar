rule TTP_XOR_MULT_DOSStub_1616 {
  strings:
    $key_1616 = { 42 7e [2] 36 66 [2] 71 64 [2] 36 75 [2] 78 79 [2] 74 73 [2] 63 78 [2] 78 36 [2] 45 }

  condition:
    any of them
}