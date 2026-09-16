rule TTP_XOR_MULT_DOSStub_08e6 {
  strings:
    $key_08e6 = { 5c 8e [2] 28 96 [2] 6f 94 [2] 28 85 [2] 66 89 [2] 6a 83 [2] 7d 88 [2] 66 c6 [2] 5b }

  condition:
    any of them
}