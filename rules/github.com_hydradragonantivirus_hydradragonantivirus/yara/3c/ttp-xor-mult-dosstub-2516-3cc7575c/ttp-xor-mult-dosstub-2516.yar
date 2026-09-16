rule TTP_XOR_MULT_DOSStub_2516 {
  strings:
    $key_2516 = { 71 7e [2] 05 66 [2] 42 64 [2] 05 75 [2] 4b 79 [2] 47 73 [2] 50 78 [2] 4b 36 [2] 76 }

  condition:
    any of them
}