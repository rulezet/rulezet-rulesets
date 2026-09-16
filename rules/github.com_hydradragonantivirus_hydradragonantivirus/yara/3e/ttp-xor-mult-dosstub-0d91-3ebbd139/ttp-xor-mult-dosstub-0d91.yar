rule TTP_XOR_MULT_DOSStub_0d91 {
  strings:
    $key_0d91 = { 59 f9 [2] 2d e1 [2] 6a e3 [2] 2d f2 [2] 63 fe [2] 6f f4 [2] 78 ff [2] 63 b1 [2] 5e }

  condition:
    any of them
}