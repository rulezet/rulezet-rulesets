rule TTP_XOR_MULT_DOSStub_2d91 {
  strings:
    $key_2d91 = { 79 f9 [2] 0d e1 [2] 4a e3 [2] 0d f2 [2] 43 fe [2] 4f f4 [2] 58 ff [2] 43 b1 [2] 7e }

  condition:
    any of them
}