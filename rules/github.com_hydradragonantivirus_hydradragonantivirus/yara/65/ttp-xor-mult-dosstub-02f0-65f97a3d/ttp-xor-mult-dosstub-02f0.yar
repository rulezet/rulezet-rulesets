rule TTP_XOR_MULT_DOSStub_02f0 {
  strings:
    $key_02f0 = { 56 98 [2] 22 80 [2] 65 82 [2] 22 93 [2] 6c 9f [2] 60 95 [2] 77 9e [2] 6c d0 [2] 51 }

  condition:
    any of them
}