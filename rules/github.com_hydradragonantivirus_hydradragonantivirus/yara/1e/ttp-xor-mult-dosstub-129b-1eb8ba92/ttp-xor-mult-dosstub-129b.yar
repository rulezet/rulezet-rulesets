rule TTP_XOR_MULT_DOSStub_129b {
  strings:
    $key_129b = { 46 f3 [2] 32 eb [2] 75 e9 [2] 32 f8 [2] 7c f4 [2] 70 fe [2] 67 f5 [2] 7c bb [2] 41 }

  condition:
    any of them
}