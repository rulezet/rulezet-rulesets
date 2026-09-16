rule TTP_XOR_MULT_DOSStub_2ca5 {
  strings:
    $key_2ca5 = { 78 cd [2] 0c d5 [2] 4b d7 [2] 0c c6 [2] 42 ca [2] 4e c0 [2] 59 cb [2] 42 85 [2] 7f }

  condition:
    any of them
}