rule TTP_XOR_MULT_DOSStub_e19b {
  strings:
    $key_e19b = { b5 f3 [2] c1 eb [2] 86 e9 [2] c1 f8 [2] 8f f4 [2] 83 fe [2] 94 f5 [2] 8f bb [2] b2 }

  condition:
    any of them
}