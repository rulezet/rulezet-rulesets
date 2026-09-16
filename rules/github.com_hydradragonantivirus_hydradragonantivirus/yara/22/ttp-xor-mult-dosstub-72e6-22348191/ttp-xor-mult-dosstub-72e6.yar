rule TTP_XOR_MULT_DOSStub_72e6 {
  strings:
    $key_72e6 = { 26 8e [2] 52 96 [2] 15 94 [2] 52 85 [2] 1c 89 [2] 10 83 [2] 07 88 [2] 1c c6 [2] 21 }

  condition:
    any of them
}