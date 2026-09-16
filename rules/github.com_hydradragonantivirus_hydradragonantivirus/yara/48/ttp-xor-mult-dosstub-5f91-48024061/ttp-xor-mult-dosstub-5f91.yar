rule TTP_XOR_MULT_DOSStub_5f91 {
  strings:
    $key_5f91 = { 0b f9 [2] 7f e1 [2] 38 e3 [2] 7f f2 [2] 31 fe [2] 3d f4 [2] 2a ff [2] 31 b1 [2] 0c }

  condition:
    any of them
}