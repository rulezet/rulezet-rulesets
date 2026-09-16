rule TTP_XOR_MULT_DOSStub_1fc1 {
  strings:
    $key_1fc1 = { 4b a9 [2] 3f b1 [2] 78 b3 [2] 3f a2 [2] 71 ae [2] 7d a4 [2] 6a af [2] 71 e1 [2] 4c }

  condition:
    any of them
}