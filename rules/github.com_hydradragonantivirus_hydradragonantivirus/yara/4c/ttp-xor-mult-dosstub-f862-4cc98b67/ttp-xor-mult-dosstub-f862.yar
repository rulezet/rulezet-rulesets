rule TTP_XOR_MULT_DOSStub_f862 {
  strings:
    $key_f862 = { ac 0a [2] d8 12 [2] 9f 10 [2] d8 01 [2] 96 0d [2] 9a 07 [2] 8d 0c [2] 96 42 [2] ab }

  condition:
    any of them
}