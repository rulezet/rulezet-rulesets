rule TTP_XOR_MULT_DOSStub_e291 {
  strings:
    $key_e291 = { b6 f9 [2] c2 e1 [2] 85 e3 [2] c2 f2 [2] 8c fe [2] 80 f4 [2] 97 ff [2] 8c b1 [2] b1 }

  condition:
    any of them
}