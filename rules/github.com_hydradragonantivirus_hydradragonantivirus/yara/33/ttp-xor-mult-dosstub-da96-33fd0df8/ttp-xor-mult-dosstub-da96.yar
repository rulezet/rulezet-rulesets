rule TTP_XOR_MULT_DOSStub_da96 {
  strings:
    $key_da96 = { 8e fe [2] fa e6 [2] bd e4 [2] fa f5 [2] b4 f9 [2] b8 f3 [2] af f8 [2] b4 b6 [2] 89 }

  condition:
    any of them
}