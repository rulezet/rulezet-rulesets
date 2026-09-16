rule TTP_XOR_MULT_DOSStub_02e9 {
  strings:
    $key_02e9 = { 56 81 [2] 22 99 [2] 65 9b [2] 22 8a [2] 6c 86 [2] 60 8c [2] 77 87 [2] 6c c9 [2] 51 }

  condition:
    any of them
}