rule TTP_XOR_MULT_DOSStub_2cb5 {
  strings:
    $key_2cb5 = { 78 dd [2] 0c c5 [2] 4b c7 [2] 0c d6 [2] 42 da [2] 4e d0 [2] 59 db [2] 42 95 [2] 7f }

  condition:
    any of them
}