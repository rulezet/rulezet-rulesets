rule TTP_XOR_MULT_DOSStub_da9b {
  strings:
    $key_da9b = { 8e f3 [2] fa eb [2] bd e9 [2] fa f8 [2] b4 f4 [2] b8 fe [2] af f5 [2] b4 bb [2] 89 }

  condition:
    any of them
}