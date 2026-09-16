rule TTP_XOR_MULT_DOSStub_1ed6 {
  strings:
    $key_1ed6 = { 4a be [2] 3e a6 [2] 79 a4 [2] 3e b5 [2] 70 b9 [2] 7c b3 [2] 6b b8 [2] 70 f6 [2] 4d }

  condition:
    any of them
}