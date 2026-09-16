rule TTP_XOR_MULT_DOSStub_5191 {
  strings:
    $key_5191 = { 05 f9 [2] 71 e1 [2] 36 e3 [2] 71 f2 [2] 3f fe [2] 33 f4 [2] 24 ff [2] 3f b1 [2] 02 }

  condition:
    any of them
}