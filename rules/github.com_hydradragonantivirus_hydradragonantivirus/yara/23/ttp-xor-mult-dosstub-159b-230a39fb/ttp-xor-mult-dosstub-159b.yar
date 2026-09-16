rule TTP_XOR_MULT_DOSStub_159b {
  strings:
    $key_159b = { 41 f3 [2] 35 eb [2] 72 e9 [2] 35 f8 [2] 7b f4 [2] 77 fe [2] 60 f5 [2] 7b bb [2] 46 }

  condition:
    any of them
}