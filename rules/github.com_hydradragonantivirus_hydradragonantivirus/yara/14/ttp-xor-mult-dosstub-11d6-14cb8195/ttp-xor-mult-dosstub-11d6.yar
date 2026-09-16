rule TTP_XOR_MULT_DOSStub_11d6 {
  strings:
    $key_11d6 = { 45 be [2] 31 a6 [2] 76 a4 [2] 31 b5 [2] 7f b9 [2] 73 b3 [2] 64 b8 [2] 7f f6 [2] 42 }

  condition:
    any of them
}