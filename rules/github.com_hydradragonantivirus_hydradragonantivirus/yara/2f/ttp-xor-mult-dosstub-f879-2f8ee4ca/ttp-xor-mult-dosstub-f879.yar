rule TTP_XOR_MULT_DOSStub_f879 {
  strings:
    $key_f879 = { ac 11 [2] d8 09 [2] 9f 0b [2] d8 1a [2] 96 16 [2] 9a 1c [2] 8d 17 [2] 96 59 [2] ab }

  condition:
    any of them
}