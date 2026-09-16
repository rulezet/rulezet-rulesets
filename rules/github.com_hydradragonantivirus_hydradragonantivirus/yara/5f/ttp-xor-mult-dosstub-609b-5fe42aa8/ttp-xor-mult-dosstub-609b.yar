rule TTP_XOR_MULT_DOSStub_609b {
  strings:
    $key_609b = { 34 f3 [2] 40 eb [2] 07 e9 [2] 40 f8 [2] 0e f4 [2] 02 fe [2] 15 f5 [2] 0e bb [2] 33 }

  condition:
    any of them
}