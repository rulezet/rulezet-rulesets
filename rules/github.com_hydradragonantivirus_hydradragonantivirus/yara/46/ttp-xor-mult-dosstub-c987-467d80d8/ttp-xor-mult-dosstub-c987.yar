rule TTP_XOR_MULT_DOSStub_c987 {
  strings:
    $key_c987 = { 9d ef [2] e9 f7 [2] ae f5 [2] e9 e4 [2] a7 e8 [2] ab e2 [2] bc e9 [2] a7 a7 [2] 9a }

  condition:
    any of them
}