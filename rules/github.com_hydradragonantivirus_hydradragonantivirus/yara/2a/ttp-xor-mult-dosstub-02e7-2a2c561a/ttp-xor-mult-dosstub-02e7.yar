rule TTP_XOR_MULT_DOSStub_02e7 {
  strings:
    $key_02e7 = { 56 8f [2] 22 97 [2] 65 95 [2] 22 84 [2] 6c 88 [2] 60 82 [2] 77 89 [2] 6c c7 [2] 51 }

  condition:
    any of them
}