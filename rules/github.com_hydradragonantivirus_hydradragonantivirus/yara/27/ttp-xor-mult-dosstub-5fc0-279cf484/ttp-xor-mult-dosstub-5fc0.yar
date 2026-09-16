rule TTP_XOR_MULT_DOSStub_5fc0 {
  strings:
    $key_5fc0 = { 0b a8 [2] 7f b0 [2] 38 b2 [2] 7f a3 [2] 31 af [2] 3d a5 [2] 2a ae [2] 31 e0 [2] 0c }

  condition:
    any of them
}