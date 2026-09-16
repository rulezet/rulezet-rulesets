rule TTP_XOR_MULT_DOSStub_6f90 {
  strings:
    $key_6f90 = { 3b f8 [2] 4f e0 [2] 08 e2 [2] 4f f3 [2] 01 ff [2] 0d f5 [2] 1a fe [2] 01 b0 [2] 3c }

  condition:
    any of them
}