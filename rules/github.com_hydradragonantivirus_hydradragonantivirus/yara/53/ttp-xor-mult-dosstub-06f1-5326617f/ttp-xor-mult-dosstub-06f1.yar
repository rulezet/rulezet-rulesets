rule TTP_XOR_MULT_DOSStub_06f1 {
  strings:
    $key_06f1 = { 52 99 [2] 26 81 [2] 61 83 [2] 26 92 [2] 68 9e [2] 64 94 [2] 73 9f [2] 68 d1 [2] 55 }

  condition:
    any of them
}