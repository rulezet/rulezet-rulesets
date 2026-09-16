rule TTP_XOR_MULT_DOSStub_24f1 {
  strings:
    $key_24f1 = { 70 99 [2] 04 81 [2] 43 83 [2] 04 92 [2] 4a 9e [2] 46 94 [2] 51 9f [2] 4a d1 [2] 77 }

  condition:
    any of them
}