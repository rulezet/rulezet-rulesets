rule TTP_XOR_MULT_DOSStub_3d9a {
  strings:
    $key_3d9a = { 69 f2 [2] 1d ea [2] 5a e8 [2] 1d f9 [2] 53 f5 [2] 5f ff [2] 48 f4 [2] 53 ba [2] 6e }

  condition:
    any of them
}