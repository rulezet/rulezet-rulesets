rule TTP_XOR_MULT_DOSStub_f8e9 {
  strings:
    $key_f8e9 = { ac 81 [2] d8 99 [2] 9f 9b [2] d8 8a [2] 96 86 [2] 9a 8c [2] 8d 87 [2] 96 c9 [2] ab }

  condition:
    any of them
}