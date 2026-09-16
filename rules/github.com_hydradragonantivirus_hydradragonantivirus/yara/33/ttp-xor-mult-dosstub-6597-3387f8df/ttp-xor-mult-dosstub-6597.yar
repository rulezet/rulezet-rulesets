rule TTP_XOR_MULT_DOSStub_6597 {
  strings:
    $key_6597 = { 31 ff [2] 45 e7 [2] 02 e5 [2] 45 f4 [2] 0b f8 [2] 07 f2 [2] 10 f9 [2] 0b b7 [2] 36 }

  condition:
    any of them
}