rule TTP_XOR_MULT_DOSStub_08a8 {
  strings:
    $key_08a8 = { 5c c0 [2] 28 d8 [2] 6f da [2] 28 cb [2] 66 c7 [2] 6a cd [2] 7d c6 [2] 66 88 [2] 5b }

  condition:
    any of them
}