rule TTP_XOR_MULT_DOSStub_7f90 {
  strings:
    $key_7f90 = { 2b f8 [2] 5f e0 [2] 18 e2 [2] 5f f3 [2] 11 ff [2] 1d f5 [2] 0a fe [2] 11 b0 [2] 2c }

  condition:
    any of them
}