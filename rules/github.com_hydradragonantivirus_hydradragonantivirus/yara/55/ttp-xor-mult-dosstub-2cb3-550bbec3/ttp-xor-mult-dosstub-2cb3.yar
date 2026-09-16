rule TTP_XOR_MULT_DOSStub_2cb3 {
  strings:
    $key_2cb3 = { 78 db [2] 0c c3 [2] 4b c1 [2] 0c d0 [2] 42 dc [2] 4e d6 [2] 59 dd [2] 42 93 [2] 7f }

  condition:
    any of them
}