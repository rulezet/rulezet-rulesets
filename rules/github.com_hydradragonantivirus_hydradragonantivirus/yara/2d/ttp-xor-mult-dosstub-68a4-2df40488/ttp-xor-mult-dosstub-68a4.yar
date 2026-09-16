rule TTP_XOR_MULT_DOSStub_68a4 {
  strings:
    $key_68a4 = { 3c cc [2] 48 d4 [2] 0f d6 [2] 48 c7 [2] 06 cb [2] 0a c1 [2] 1d ca [2] 06 84 [2] 3b }

  condition:
    any of them
}