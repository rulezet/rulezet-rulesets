rule TTP_XOR_MULT_DOSStub_f832 {
  strings:
    $key_f832 = { ac 5a [2] d8 42 [2] 9f 40 [2] d8 51 [2] 96 5d [2] 9a 57 [2] 8d 5c [2] 96 12 [2] ab }

  condition:
    any of them
}