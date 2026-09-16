rule TTP_XOR_MULT_DOSStub_1197 {
  strings:
    $key_1197 = { 45 ff [2] 31 e7 [2] 76 e5 [2] 31 f4 [2] 7f f8 [2] 73 f2 [2] 64 f9 [2] 7f b7 [2] 42 }

  condition:
    any of them
}