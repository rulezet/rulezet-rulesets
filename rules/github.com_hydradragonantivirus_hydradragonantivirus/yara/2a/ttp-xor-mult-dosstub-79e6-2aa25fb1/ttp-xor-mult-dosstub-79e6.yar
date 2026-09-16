rule TTP_XOR_MULT_DOSStub_79e6 {
  strings:
    $key_79e6 = { 2d 8e [2] 59 96 [2] 1e 94 [2] 59 85 [2] 17 89 [2] 1b 83 [2] 0c 88 [2] 17 c6 [2] 2a }

  condition:
    any of them
}