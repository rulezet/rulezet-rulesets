rule TTP_XOR_MULT_DOSStub_749b {
  strings:
    $key_749b = { 20 f3 [2] 54 eb [2] 13 e9 [2] 54 f8 [2] 1a f4 [2] 16 fe [2] 01 f5 [2] 1a bb [2] 27 }

  condition:
    any of them
}