rule TTP_XOR_MULT_DOSStub_379b {
  strings:
    $key_379b = { 63 f3 [2] 17 eb [2] 50 e9 [2] 17 f8 [2] 59 f4 [2] 55 fe [2] 42 f5 [2] 59 bb [2] 64 }

  condition:
    any of them
}