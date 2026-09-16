rule TTP_XOR_MULT_DOSStub_219b {
  strings:
    $key_219b = { 75 f3 [2] 01 eb [2] 46 e9 [2] 01 f8 [2] 4f f4 [2] 43 fe [2] 54 f5 [2] 4f bb [2] 72 }

  condition:
    any of them
}