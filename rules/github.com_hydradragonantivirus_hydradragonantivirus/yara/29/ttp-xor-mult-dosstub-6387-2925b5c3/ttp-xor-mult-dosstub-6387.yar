rule TTP_XOR_MULT_DOSStub_6387 {
  strings:
    $key_6387 = { 37 ef [2] 43 f7 [2] 04 f5 [2] 43 e4 [2] 0d e8 [2] 01 e2 [2] 16 e9 [2] 0d a7 [2] 30 }

  condition:
    any of them
}