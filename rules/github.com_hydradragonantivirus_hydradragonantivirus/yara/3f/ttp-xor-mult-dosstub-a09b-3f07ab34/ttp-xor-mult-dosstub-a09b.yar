rule TTP_XOR_MULT_DOSStub_a09b {
  strings:
    $key_a09b = { f4 f3 [2] 80 eb [2] c7 e9 [2] 80 f8 [2] ce f4 [2] c2 fe [2] d5 f5 [2] ce bb [2] f3 }

  condition:
    any of them
}