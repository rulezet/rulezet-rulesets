rule TTP_XOR_MULT_DOSStub_0191 {
  strings:
    $key_0191 = { 55 f9 [2] 21 e1 [2] 66 e3 [2] 21 f2 [2] 6f fe [2] 63 f4 [2] 74 ff [2] 6f b1 [2] 52 }

  condition:
    any of them
}