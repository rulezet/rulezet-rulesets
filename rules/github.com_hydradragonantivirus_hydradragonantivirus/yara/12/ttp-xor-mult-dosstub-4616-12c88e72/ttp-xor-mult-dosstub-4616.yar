rule TTP_XOR_MULT_DOSStub_4616 {
  strings:
    $key_4616 = { 12 7e [2] 66 66 [2] 21 64 [2] 66 75 [2] 28 79 [2] 24 73 [2] 33 78 [2] 28 36 [2] 15 }

  condition:
    any of them
}