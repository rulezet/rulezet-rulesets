rule TTP_XOR_MULT_DOSStub_7291 {
  strings:
    $key_7291 = { 26 f9 [2] 52 e1 [2] 15 e3 [2] 52 f2 [2] 1c fe [2] 10 f4 [2] 07 ff [2] 1c b1 [2] 21 }

  condition:
    any of them
}