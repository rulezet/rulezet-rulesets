rule TTP_XOR_MULT_DOSStub_0091 {
  strings:
    $key_0091 = { 54 f9 [2] 20 e1 [2] 67 e3 [2] 20 f2 [2] 6e fe [2] 62 f4 [2] 75 ff [2] 6e b1 [2] 53 }

  condition:
    any of them
}