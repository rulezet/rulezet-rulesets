rule TTP_XOR_MULT_DOSStub_1fb9 {
  strings:
    $key_1fb9 = { 4b d1 [2] 3f c9 [2] 78 cb [2] 3f da [2] 71 d6 [2] 7d dc [2] 6a d7 [2] 71 99 [2] 4c }

  condition:
    any of them
}