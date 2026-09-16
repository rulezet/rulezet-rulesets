rule TTP_XOR_MULT_DOSStub_f8e8 {
  strings:
    $key_f8e8 = { ac 80 [2] d8 98 [2] 9f 9a [2] d8 8b [2] 96 87 [2] 9a 8d [2] 8d 86 [2] 96 c8 [2] ab }

  condition:
    any of them
}