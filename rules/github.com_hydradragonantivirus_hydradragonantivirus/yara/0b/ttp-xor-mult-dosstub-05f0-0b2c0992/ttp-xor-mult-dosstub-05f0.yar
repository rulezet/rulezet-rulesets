rule TTP_XOR_MULT_DOSStub_05f0 {
  strings:
    $key_05f0 = { 51 98 [2] 25 80 [2] 62 82 [2] 25 93 [2] 6b 9f [2] 67 95 [2] 70 9e [2] 6b d0 [2] 56 }

  condition:
    any of them
}