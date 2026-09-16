rule TTP_XOR_MULT_DOSStub_409b {
  strings:
    $key_409b = { 14 f3 [2] 60 eb [2] 27 e9 [2] 60 f8 [2] 2e f4 [2] 22 fe [2] 35 f5 [2] 2e bb [2] 13 }

  condition:
    any of them
}