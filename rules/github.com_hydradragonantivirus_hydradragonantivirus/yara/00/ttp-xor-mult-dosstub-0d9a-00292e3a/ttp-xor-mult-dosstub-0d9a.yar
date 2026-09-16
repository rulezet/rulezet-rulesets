rule TTP_XOR_MULT_DOSStub_0d9a {
  strings:
    $key_0d9a = { 59 f2 [2] 2d ea [2] 6a e8 [2] 2d f9 [2] 63 f5 [2] 6f ff [2] 78 f4 [2] 63 ba [2] 5e }

  condition:
    any of them
}