rule TTP_XOR_MULT_DOSStub_5eee {
  strings:
    $key_5eee = { 0a 86 [2] 7e 9e [2] 39 9c [2] 7e 8d [2] 30 81 [2] 3c 8b [2] 2b 80 [2] 30 ce [2] 0d }

  condition:
    any of them
}