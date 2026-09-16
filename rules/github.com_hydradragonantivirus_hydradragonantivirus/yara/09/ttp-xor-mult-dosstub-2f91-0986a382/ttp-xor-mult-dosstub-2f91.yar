rule TTP_XOR_MULT_DOSStub_2f91 {
  strings:
    $key_2f91 = { 7b f9 [2] 0f e1 [2] 48 e3 [2] 0f f2 [2] 41 fe [2] 4d f4 [2] 5a ff [2] 41 b1 [2] 7c }

  condition:
    any of them
}