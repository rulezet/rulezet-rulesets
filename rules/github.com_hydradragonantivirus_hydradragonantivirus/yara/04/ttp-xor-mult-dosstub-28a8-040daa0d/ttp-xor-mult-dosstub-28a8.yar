rule TTP_XOR_MULT_DOSStub_28a8 {
  strings:
    $key_28a8 = { 7c c0 [2] 08 d8 [2] 4f da [2] 08 cb [2] 46 c7 [2] 4a cd [2] 5d c6 [2] 46 88 [2] 7b }

  condition:
    any of them
}