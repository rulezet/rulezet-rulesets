rule TTP_XOR_MULT_DOSStub_6fc1 {
  strings:
    $key_6fc1 = { 3b a9 [2] 4f b1 [2] 08 b3 [2] 4f a2 [2] 01 ae [2] 0d a4 [2] 1a af [2] 01 e1 [2] 3c }

  condition:
    any of them
}