rule TTP_XOR_MULT_DOSStub_11c7 {
  strings:
    $key_11c7 = { 45 af [2] 31 b7 [2] 76 b5 [2] 31 a4 [2] 7f a8 [2] 73 a2 [2] 64 a9 [2] 7f e7 [2] 42 }

  condition:
    any of them
}