rule TTP_XOR_MULT_DOSStub_4cee {
  strings:
    $key_4cee = { 18 86 [2] 6c 9e [2] 2b 9c [2] 6c 8d [2] 22 81 [2] 2e 8b [2] 39 80 [2] 22 ce [2] 1f }

  condition:
    any of them
}