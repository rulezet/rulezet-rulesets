rule TTP_XOR_MULT_DOSStub_36f0 {
  strings:
    $key_36f0 = { 62 98 [2] 16 80 [2] 51 82 [2] 16 93 [2] 58 9f [2] 54 95 [2] 43 9e [2] 58 d0 [2] 65 }

  condition:
    any of them
}