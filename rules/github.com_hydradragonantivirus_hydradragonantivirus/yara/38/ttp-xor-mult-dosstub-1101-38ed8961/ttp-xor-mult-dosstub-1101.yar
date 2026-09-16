rule TTP_XOR_MULT_DOSStub_1101 {
  strings:
    $key_1101 = { 45 69 [2] 31 71 [2] 76 73 [2] 31 62 [2] 7f 6e [2] 73 64 [2] 64 6f [2] 7f 21 [2] 42 }

  condition:
    any of them
}