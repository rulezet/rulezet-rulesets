rule TTP_XOR_MULT_DOSStub_3091 {
  strings:
    $key_3091 = { 64 f9 [2] 10 e1 [2] 57 e3 [2] 10 f2 [2] 5e fe [2] 52 f4 [2] 45 ff [2] 5e b1 [2] 63 }

  condition:
    any of them
}