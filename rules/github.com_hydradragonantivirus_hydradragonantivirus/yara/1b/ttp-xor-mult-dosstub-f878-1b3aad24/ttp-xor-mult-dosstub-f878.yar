rule TTP_XOR_MULT_DOSStub_f878 {
  strings:
    $key_f878 = { ac 10 [2] d8 08 [2] 9f 0a [2] d8 1b [2] 96 17 [2] 9a 1d [2] 8d 16 [2] 96 58 [2] ab }

  condition:
    any of them
}