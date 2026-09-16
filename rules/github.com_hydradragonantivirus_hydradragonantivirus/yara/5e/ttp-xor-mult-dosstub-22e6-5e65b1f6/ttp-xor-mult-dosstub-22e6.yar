rule TTP_XOR_MULT_DOSStub_22e6 {
  strings:
    $key_22e6 = { 76 8e [2] 02 96 [2] 45 94 [2] 02 85 [2] 4c 89 [2] 40 83 [2] 57 88 [2] 4c c6 [2] 71 }

  condition:
    any of them
}