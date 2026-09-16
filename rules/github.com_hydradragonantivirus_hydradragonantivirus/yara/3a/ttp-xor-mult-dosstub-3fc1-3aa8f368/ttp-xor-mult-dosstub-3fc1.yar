rule TTP_XOR_MULT_DOSStub_3fc1 {
  strings:
    $key_3fc1 = { 6b a9 [2] 1f b1 [2] 58 b3 [2] 1f a2 [2] 51 ae [2] 5d a4 [2] 4a af [2] 51 e1 [2] 6c }

  condition:
    any of them
}