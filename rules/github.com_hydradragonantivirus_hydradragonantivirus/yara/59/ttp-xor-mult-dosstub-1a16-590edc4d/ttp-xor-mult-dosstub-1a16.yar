rule TTP_XOR_MULT_DOSStub_1a16 {
  strings:
    $key_1a16 = { 4e 7e [2] 3a 66 [2] 7d 64 [2] 3a 75 [2] 74 79 [2] 78 73 [2] 6f 78 [2] 74 36 [2] 49 }

  condition:
    any of them
}