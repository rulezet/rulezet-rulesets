rule TTP_XOR_MULT_DOSStub_639b {
  strings:
    $key_639b = { 37 f3 [2] 43 eb [2] 04 e9 [2] 43 f8 [2] 0d f4 [2] 01 fe [2] 16 f5 [2] 0d bb [2] 30 }

  condition:
    any of them
}