rule TTP_XOR_MULT_DOSStub_02f1 {
  strings:
    $key_02f1 = { 56 99 [2] 22 81 [2] 65 83 [2] 22 92 [2] 6c 9e [2] 60 94 [2] 77 9f [2] 6c d1 [2] 51 }

  condition:
    any of them
}