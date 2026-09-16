rule TTP_XOR_MULT_DOSStub_4c16 {
  strings:
    $key_4c16 = { 18 7e [2] 6c 66 [2] 2b 64 [2] 6c 75 [2] 22 79 [2] 2e 73 [2] 39 78 [2] 22 36 [2] 1f }

  condition:
    any of them
}