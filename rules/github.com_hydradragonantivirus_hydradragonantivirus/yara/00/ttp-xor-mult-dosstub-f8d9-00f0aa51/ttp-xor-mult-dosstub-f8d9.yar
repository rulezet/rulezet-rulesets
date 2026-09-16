rule TTP_XOR_MULT_DOSStub_f8d9 {
  strings:
    $key_f8d9 = { ac b1 [2] d8 a9 [2] 9f ab [2] d8 ba [2] 96 b6 [2] 9a bc [2] 8d b7 [2] 96 f9 [2] ab }

  condition:
    any of them
}