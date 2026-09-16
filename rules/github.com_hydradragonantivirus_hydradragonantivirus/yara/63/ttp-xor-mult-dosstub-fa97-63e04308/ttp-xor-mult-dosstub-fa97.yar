rule TTP_XOR_MULT_DOSStub_fa97 {
  strings:
    $key_fa97 = { ae ff [2] da e7 [2] 9d e5 [2] da f4 [2] 94 f8 [2] 98 f2 [2] 8f f9 [2] 94 b7 [2] a9 }

  condition:
    any of them
}