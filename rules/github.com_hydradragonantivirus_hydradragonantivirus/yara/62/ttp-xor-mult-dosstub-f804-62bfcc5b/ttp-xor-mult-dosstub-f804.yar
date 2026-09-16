rule TTP_XOR_MULT_DOSStub_f804 {
  strings:
    $key_f804 = { ac 6c [2] d8 74 [2] 9f 76 [2] d8 67 [2] 96 6b [2] 9a 61 [2] 8d 6a [2] 96 24 [2] ab }

  condition:
    any of them
}