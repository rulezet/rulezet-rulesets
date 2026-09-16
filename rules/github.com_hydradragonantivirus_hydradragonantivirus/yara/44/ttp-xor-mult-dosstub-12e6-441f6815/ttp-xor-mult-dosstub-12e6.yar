rule TTP_XOR_MULT_DOSStub_12e6 {
  strings:
    $key_12e6 = { 46 8e [2] 32 96 [2] 75 94 [2] 32 85 [2] 7c 89 [2] 70 83 [2] 67 88 [2] 7c c6 [2] 41 }

  condition:
    any of them
}