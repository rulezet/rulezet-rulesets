rule TTP_XOR_MULT_DOSStub_1291 {
  strings:
    $key_1291 = { 46 f9 [2] 32 e1 [2] 75 e3 [2] 32 f2 [2] 7c fe [2] 70 f4 [2] 67 ff [2] 7c b1 [2] 41 }

  condition:
    any of them
}