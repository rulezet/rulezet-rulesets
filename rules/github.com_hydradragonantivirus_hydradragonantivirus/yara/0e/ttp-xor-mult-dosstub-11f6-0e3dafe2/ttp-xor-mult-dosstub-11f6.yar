rule TTP_XOR_MULT_DOSStub_11f6 {
  strings:
    $key_11f6 = { 45 9e [2] 31 86 [2] 76 84 [2] 31 95 [2] 7f 99 [2] 73 93 [2] 64 98 [2] 7f d6 [2] 42 }

  condition:
    any of them
}