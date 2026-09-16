rule TTP_XOR_MULT_DOSStub_209b {
  strings:
    $key_209b = { 74 f3 [2] 00 eb [2] 47 e9 [2] 00 f8 [2] 4e f4 [2] 42 fe [2] 55 f5 [2] 4e bb [2] 73 }

  condition:
    any of them
}