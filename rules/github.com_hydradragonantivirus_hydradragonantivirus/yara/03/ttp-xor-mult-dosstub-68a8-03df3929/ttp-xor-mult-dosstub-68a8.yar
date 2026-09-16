rule TTP_XOR_MULT_DOSStub_68a8 {
  strings:
    $key_68a8 = { 3c c0 [2] 48 d8 [2] 0f da [2] 48 cb [2] 06 c7 [2] 0a cd [2] 1d c6 [2] 06 88 [2] 3b }

  condition:
    any of them
}