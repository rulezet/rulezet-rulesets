rule TTP_XOR_MULT_DOSStub_6cee {
  strings:
    $key_6cee = { 38 86 [2] 4c 9e [2] 0b 9c [2] 4c 8d [2] 02 81 [2] 0e 8b [2] 19 80 [2] 02 ce [2] 3f }

  condition:
    any of them
}