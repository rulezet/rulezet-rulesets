rule TTP_XOR_MULT_DOSStub_f8b2 {
  strings:
    $key_f8b2 = { ac da [2] d8 c2 [2] 9f c0 [2] d8 d1 [2] 96 dd [2] 9a d7 [2] 8d dc [2] 96 92 [2] ab }

  condition:
    any of them
}