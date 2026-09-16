rule TTP_XOR_MULT_DOSStub_f8b3 {
  strings:
    $key_f8b3 = { ac db [2] d8 c3 [2] 9f c1 [2] d8 d0 [2] 96 dc [2] 9a d6 [2] 8d dd [2] 96 93 [2] ab }

  condition:
    any of them
}