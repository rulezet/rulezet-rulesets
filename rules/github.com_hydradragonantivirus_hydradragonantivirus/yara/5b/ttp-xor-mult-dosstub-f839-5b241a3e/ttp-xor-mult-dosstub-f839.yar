rule TTP_XOR_MULT_DOSStub_f839 {
  strings:
    $key_f839 = { ac 51 [2] d8 49 [2] 9f 4b [2] d8 5a [2] 96 56 [2] 9a 5c [2] 8d 57 [2] 96 19 [2] ab }

  condition:
    any of them
}