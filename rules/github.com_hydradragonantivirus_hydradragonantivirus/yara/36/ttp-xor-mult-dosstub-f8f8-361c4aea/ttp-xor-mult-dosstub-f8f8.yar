rule TTP_XOR_MULT_DOSStub_f8f8 {
  strings:
    $key_f8f8 = { ac 90 [2] d8 88 [2] 9f 8a [2] d8 9b [2] 96 97 [2] 9a 9d [2] 8d 96 [2] 96 d8 [2] ab }

  condition:
    any of them
}