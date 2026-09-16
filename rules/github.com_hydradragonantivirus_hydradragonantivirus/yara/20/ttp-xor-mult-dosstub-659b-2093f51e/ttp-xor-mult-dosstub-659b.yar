rule TTP_XOR_MULT_DOSStub_659b {
  strings:
    $key_659b = { 31 f3 [2] 45 eb [2] 02 e9 [2] 45 f8 [2] 0b f4 [2] 07 fe [2] 10 f5 [2] 0b bb [2] 36 }

  condition:
    any of them
}