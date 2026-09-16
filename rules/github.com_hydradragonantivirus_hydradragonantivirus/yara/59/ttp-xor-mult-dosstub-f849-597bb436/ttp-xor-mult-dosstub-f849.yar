rule TTP_XOR_MULT_DOSStub_f849 {
  strings:
    $key_f849 = { ac 21 [2] d8 39 [2] 9f 3b [2] d8 2a [2] 96 26 [2] 9a 2c [2] 8d 27 [2] 96 69 [2] ab }

  condition:
    any of them
}