rule TTP_XOR_MULT_DOSStub_4f90 {
  strings:
    $key_4f90 = { 1b f8 [2] 6f e0 [2] 28 e2 [2] 6f f3 [2] 21 ff [2] 2d f5 [2] 3a fe [2] 21 b0 [2] 1c }

  condition:
    any of them
}