rule TTP_XOR_MULT_DOSStub_5fc1 {
  strings:
    $key_5fc1 = { 0b a9 [2] 7f b1 [2] 38 b3 [2] 7f a2 [2] 31 ae [2] 3d a4 [2] 2a af [2] 31 e1 [2] 0c }

  condition:
    any of them
}