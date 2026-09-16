rule TTP_XOR_MULT_DOSStub_e797 {
  strings:
    $key_e797 = { b3 ff [2] c7 e7 [2] 80 e5 [2] c7 f4 [2] 89 f8 [2] 85 f2 [2] 92 f9 [2] 89 b7 [2] b4 }

  condition:
    any of them
}