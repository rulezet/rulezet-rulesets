rule TTP_XOR_MULT_DOSStub_2d9a {
  strings:
    $key_2d9a = { 79 f2 [2] 0d ea [2] 4a e8 [2] 0d f9 [2] 43 f5 [2] 4f ff [2] 58 f4 [2] 43 ba [2] 7e }

  condition:
    any of them
}