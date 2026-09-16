rule TTP_XOR_MULT_DOSStub_f8e4 {
  strings:
    $key_f8e4 = { ac 8c [2] d8 94 [2] 9f 96 [2] d8 87 [2] 96 8b [2] 9a 81 [2] 8d 8a [2] 96 c4 [2] ab }

  condition:
    any of them
}