rule TTP_XOR_MULT_DOSStub_3cee {
  strings:
    $key_3cee = { 68 86 [2] 1c 9e [2] 5b 9c [2] 1c 8d [2] 52 81 [2] 5e 8b [2] 49 80 [2] 52 ce [2] 6f }

  condition:
    any of them
}