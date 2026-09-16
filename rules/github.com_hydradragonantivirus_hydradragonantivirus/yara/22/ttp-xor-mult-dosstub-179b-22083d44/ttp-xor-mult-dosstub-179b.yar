rule TTP_XOR_MULT_DOSStub_179b {
  strings:
    $key_179b = { 43 f3 [2] 37 eb [2] 70 e9 [2] 37 f8 [2] 79 f4 [2] 75 fe [2] 62 f5 [2] 79 bb [2] 44 }

  condition:
    any of them
}