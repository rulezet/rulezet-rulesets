rule TTP_XOR_MULT_DOSStub_06f6 {
  strings:
    $key_06f6 = { 52 9e [2] 26 86 [2] 61 84 [2] 26 95 [2] 68 99 [2] 64 93 [2] 73 98 [2] 68 d6 [2] 55 }

  condition:
    any of them
}