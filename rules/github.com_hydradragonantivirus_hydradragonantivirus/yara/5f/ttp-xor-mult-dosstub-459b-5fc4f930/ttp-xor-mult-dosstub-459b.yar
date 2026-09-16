rule TTP_XOR_MULT_DOSStub_459b {
  strings:
    $key_459b = { 11 f3 [2] 65 eb [2] 22 e9 [2] 65 f8 [2] 2b f4 [2] 27 fe [2] 30 f5 [2] 2b bb [2] 16 }

  condition:
    any of them
}