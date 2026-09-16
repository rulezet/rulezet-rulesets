rule TTP_XOR_MULT_DOSStub_f842 {
  strings:
    $key_f842 = { ac 2a [2] d8 32 [2] 9f 30 [2] d8 21 [2] 96 2d [2] 9a 27 [2] 8d 2c [2] 96 62 [2] ab }

  condition:
    any of them
}