rule TTP_XOR_MULT_DOSStub_4f91 {
  strings:
    $key_4f91 = { 1b f9 [2] 6f e1 [2] 28 e3 [2] 6f f2 [2] 21 fe [2] 2d f4 [2] 3a ff [2] 21 b1 [2] 1c }

  condition:
    any of them
}