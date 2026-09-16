rule TTP_XOR_MULT_DOSStub_5ca4 {
  strings:
    $key_5ca4 = { 08 cc [2] 7c d4 [2] 3b d6 [2] 7c c7 [2] 32 cb [2] 3e c1 [2] 29 ca [2] 32 84 [2] 0f }

  condition:
    any of them
}