rule TTP_XOR_MULT_DOSStub_02e6 {
  strings:
    $key_02e6 = { 56 8e [2] 22 96 [2] 65 94 [2] 22 85 [2] 6c 89 [2] 60 83 [2] 77 88 [2] 6c c6 [2] 51 }

  condition:
    any of them
}