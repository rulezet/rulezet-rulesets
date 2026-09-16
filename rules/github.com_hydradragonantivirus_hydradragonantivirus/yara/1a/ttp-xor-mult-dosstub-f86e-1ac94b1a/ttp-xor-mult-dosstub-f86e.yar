rule TTP_XOR_MULT_DOSStub_f86e {
  strings:
    $key_f86e = { ac 06 [2] d8 1e [2] 9f 1c [2] d8 0d [2] 96 01 [2] 9a 0b [2] 8d 00 [2] 96 4e [2] ab }

  condition:
    any of them
}