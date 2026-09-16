rule TTP_XOR_MULT_DOSStub_7aee {
  strings:
    $key_7aee = { 2e 86 [2] 5a 9e [2] 1d 9c [2] 5a 8d [2] 14 81 [2] 18 8b [2] 0f 80 [2] 14 ce [2] 29 }

  condition:
    any of them
}