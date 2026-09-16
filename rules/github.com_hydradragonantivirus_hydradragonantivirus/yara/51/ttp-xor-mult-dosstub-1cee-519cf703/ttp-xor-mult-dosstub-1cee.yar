rule TTP_XOR_MULT_DOSStub_1cee {
  strings:
    $key_1cee = { 48 86 [2] 3c 9e [2] 7b 9c [2] 3c 8d [2] 72 81 [2] 7e 8b [2] 69 80 [2] 72 ce [2] 4f }

  condition:
    any of them
}