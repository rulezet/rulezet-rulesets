rule TTP_XOR_MULT_DOSStub_0197 {
  strings:
    $key_0197 = { 55 ff [2] 21 e7 [2] 66 e5 [2] 21 f4 [2] 6f f8 [2] 63 f2 [2] 74 f9 [2] 6f b7 [2] 52 }

  condition:
    any of them
}