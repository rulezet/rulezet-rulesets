rule TTP_XOR_MULT_DOSStub_f86f {
  strings:
    $key_f86f = { ac 07 [2] d8 1f [2] 9f 1d [2] d8 0c [2] 96 00 [2] 9a 0a [2] 8d 01 [2] 96 4f [2] ab }

  condition:
    any of them
}