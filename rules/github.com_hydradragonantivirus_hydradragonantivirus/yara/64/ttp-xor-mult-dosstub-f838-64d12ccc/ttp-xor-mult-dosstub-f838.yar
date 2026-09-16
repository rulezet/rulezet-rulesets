rule TTP_XOR_MULT_DOSStub_f838 {
  strings:
    $key_f838 = { ac 50 [2] d8 48 [2] 9f 4a [2] d8 5b [2] 96 57 [2] 9a 5d [2] 8d 56 [2] 96 18 [2] ab }

  condition:
    any of them
}