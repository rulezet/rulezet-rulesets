rule TTP_XOR_MULT_DOSStub_f843 {
  strings:
    $key_f843 = { ac 2b [2] d8 33 [2] 9f 31 [2] d8 20 [2] 96 2c [2] 9a 26 [2] 8d 2d [2] 96 63 [2] ab }

  condition:
    any of them
}