rule TTP_XOR_MULT_DOSStub_c490 {
  strings:
    $key_c490 = { 90 f8 [2] e4 e0 [2] a3 e2 [2] e4 f3 [2] aa ff [2] a6 f5 [2] b1 fe [2] aa b0 [2] 97 }

  condition:
    any of them
}