rule TTP_XOR_MULT_DOSStub_109b {
  strings:
    $key_109b = { 44 f3 [2] 30 eb [2] 77 e9 [2] 30 f8 [2] 7e f4 [2] 72 fe [2] 65 f5 [2] 7e bb [2] 43 }

  condition:
    any of them
}