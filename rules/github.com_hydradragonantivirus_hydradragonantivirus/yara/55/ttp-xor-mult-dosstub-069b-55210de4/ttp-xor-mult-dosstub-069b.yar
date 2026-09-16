rule TTP_XOR_MULT_DOSStub_069b {
  strings:
    $key_069b = { 52 f3 [2] 26 eb [2] 61 e9 [2] 26 f8 [2] 68 f4 [2] 64 fe [2] 73 f5 [2] 68 bb [2] 55 }

  condition:
    any of them
}