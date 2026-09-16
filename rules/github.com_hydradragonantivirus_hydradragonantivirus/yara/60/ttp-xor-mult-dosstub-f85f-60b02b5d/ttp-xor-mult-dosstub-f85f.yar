rule TTP_XOR_MULT_DOSStub_f85f {
  strings:
    $key_f85f = { ac 37 [2] d8 2f [2] 9f 2d [2] d8 3c [2] 96 30 [2] 9a 3a [2] 8d 31 [2] 96 7f [2] ab }

  condition:
    any of them
}