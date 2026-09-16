rule TTP_XOR_MULT_DOSStub_f869 {
  strings:
    $key_f869 = { ac 01 [2] d8 19 [2] 9f 1b [2] d8 0a [2] 96 06 [2] 9a 0c [2] 8d 07 [2] 96 49 [2] ab }

  condition:
    any of them
}