rule TTP_XOR_MULT_DOSStub_6091 {
  strings:
    $key_6091 = { 34 f9 [2] 40 e1 [2] 07 e3 [2] 40 f2 [2] 0e fe [2] 02 f4 [2] 15 ff [2] 0e b1 [2] 33 }

  condition:
    any of them
}