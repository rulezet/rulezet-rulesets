rule TTP_XOR_MULT_DOSStub_169b {
  strings:
    $key_169b = { 42 f3 [2] 36 eb [2] 71 e9 [2] 36 f8 [2] 78 f4 [2] 74 fe [2] 63 f5 [2] 78 bb [2] 45 }

  condition:
    any of them
}