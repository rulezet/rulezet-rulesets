rule TTP_XOR_MULT_DOSStub_6fb9 {
  strings:
    $key_6fb9 = { 3b d1 [2] 4f c9 [2] 08 cb [2] 4f da [2] 01 d6 [2] 0d dc [2] 1a d7 [2] 01 99 [2] 3c }

  condition:
    any of them
}