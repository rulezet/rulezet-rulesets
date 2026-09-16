rule TTP_XOR_MULT_DOSStub_0f91 {
  strings:
    $key_0f91 = { 5b f9 [2] 2f e1 [2] 68 e3 [2] 2f f2 [2] 61 fe [2] 6d f4 [2] 7a ff [2] 61 b1 [2] 5c }

  condition:
    any of them
}