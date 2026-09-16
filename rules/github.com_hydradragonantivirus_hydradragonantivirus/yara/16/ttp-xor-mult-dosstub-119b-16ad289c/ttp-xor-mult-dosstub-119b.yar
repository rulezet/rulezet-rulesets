rule TTP_XOR_MULT_DOSStub_119b {
  strings:
    $key_119b = { 45 f3 [2] 31 eb [2] 76 e9 [2] 31 f8 [2] 7f f4 [2] 73 fe [2] 64 f5 [2] 7f bb [2] 42 }

  condition:
    any of them
}