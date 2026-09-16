rule TTP_XOR_MULT_DOSStub_5fc2 {
  strings:
    $key_5fc2 = { 0b aa [2] 7f b2 [2] 38 b0 [2] 7f a1 [2] 31 ad [2] 3d a7 [2] 2a ac [2] 31 e2 [2] 0c }

  condition:
    any of them
}