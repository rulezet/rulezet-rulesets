rule TTP_XOR_MULT_DOSStub_829b {
  strings:
    $key_829b = { d6 f3 [2] a2 eb [2] e5 e9 [2] a2 f8 [2] ec f4 [2] e0 fe [2] f7 f5 [2] ec bb [2] d1 }

  condition:
    any of them
}