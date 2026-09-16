rule TTP_XOR_MULT_DOSStub_1ca5 {
  strings:
    $key_1ca5 = { 48 cd [2] 3c d5 [2] 7b d7 [2] 3c c6 [2] 72 ca [2] 7e c0 [2] 69 cb [2] 72 85 [2] 4f }

  condition:
    any of them
}