rule TTP_XOR_MULT_DOSStub_f844 {
  strings:
    $key_f844 = { ac 2c [2] d8 34 [2] 9f 36 [2] d8 27 [2] 96 2b [2] 9a 21 [2] 8d 2a [2] 96 64 [2] ab }

  condition:
    any of them
}