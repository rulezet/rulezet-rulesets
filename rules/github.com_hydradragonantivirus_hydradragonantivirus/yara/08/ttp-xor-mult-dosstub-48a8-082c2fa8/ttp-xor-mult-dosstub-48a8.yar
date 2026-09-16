rule TTP_XOR_MULT_DOSStub_48a8 {
  strings:
    $key_48a8 = { 1c c0 [2] 68 d8 [2] 2f da [2] 68 cb [2] 26 c7 [2] 2a cd [2] 3d c6 [2] 26 88 [2] 1b }

  condition:
    any of them
}