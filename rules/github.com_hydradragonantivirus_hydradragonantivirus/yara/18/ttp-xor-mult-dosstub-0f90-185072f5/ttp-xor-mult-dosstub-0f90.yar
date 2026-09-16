rule TTP_XOR_MULT_DOSStub_0f90 {
  strings:
    $key_0f90 = { 5b f8 [2] 2f e0 [2] 68 e2 [2] 2f f3 [2] 61 ff [2] 6d f5 [2] 7a fe [2] 61 b0 [2] 5c }

  condition:
    any of them
}