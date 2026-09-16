rule TTP_XOR_MULT_DOSStub_7091 {
  strings:
    $key_7091 = { 24 f9 [2] 50 e1 [2] 17 e3 [2] 50 f2 [2] 1e fe [2] 12 f4 [2] 05 ff [2] 1e b1 [2] 23 }

  condition:
    any of them
}