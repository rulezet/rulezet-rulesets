rule TTP_XOR_MULT_DOSStub_0597 {
  strings:
    $key_0597 = { 51 ff [2] 25 e7 [2] 62 e5 [2] 25 f4 [2] 6b f8 [2] 67 f2 [2] 70 f9 [2] 6b b7 [2] 56 }

  condition:
    any of them
}