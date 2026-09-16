rule TTP_XOR_MULT_DOSStub_27f0 {
  strings:
    $key_27f0 = { 73 98 [2] 07 80 [2] 40 82 [2] 07 93 [2] 49 9f [2] 45 95 [2] 52 9e [2] 49 d0 [2] 74 }

  condition:
    any of them
}