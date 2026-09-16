rule TTP_XOR_MULT_DOSStub_6eee {
  strings:
    $key_6eee = { 3a 86 [2] 4e 9e [2] 09 9c [2] 4e 8d [2] 00 81 [2] 0c 8b [2] 1b 80 [2] 00 ce [2] 3d }

  condition:
    any of them
}