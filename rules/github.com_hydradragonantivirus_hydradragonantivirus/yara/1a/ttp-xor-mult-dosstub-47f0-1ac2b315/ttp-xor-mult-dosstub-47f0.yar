rule TTP_XOR_MULT_DOSStub_47f0 {
  strings:
    $key_47f0 = { 13 98 [2] 67 80 [2] 20 82 [2] 67 93 [2] 29 9f [2] 25 95 [2] 32 9e [2] 29 d0 [2] 14 }

  condition:
    any of them
}