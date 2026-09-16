rule TTP_XOR_MULT_DOSStub_7cee {
  strings:
    $key_7cee = { 28 86 [2] 5c 9e [2] 1b 9c [2] 5c 8d [2] 12 81 [2] 1e 8b [2] 09 80 [2] 12 ce [2] 2f }

  condition:
    any of them
}