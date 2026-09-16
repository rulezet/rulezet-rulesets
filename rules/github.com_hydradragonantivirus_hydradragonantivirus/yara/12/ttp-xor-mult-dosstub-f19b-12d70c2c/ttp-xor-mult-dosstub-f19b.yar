rule TTP_XOR_MULT_DOSStub_f19b {
  strings:
    $key_f19b = { a5 f3 [2] d1 eb [2] 96 e9 [2] d1 f8 [2] 9f f4 [2] 93 fe [2] 84 f5 [2] 9f bb [2] a2 }

  condition:
    any of them
}