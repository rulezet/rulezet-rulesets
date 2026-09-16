rule TTP_XOR_MULT_DOSStub_e791 {
  strings:
    $key_e791 = { b3 f9 [2] c7 e1 [2] 80 e3 [2] c7 f2 [2] 89 fe [2] 85 f4 [2] 92 ff [2] 89 b1 [2] b4 }

  condition:
    any of them
}