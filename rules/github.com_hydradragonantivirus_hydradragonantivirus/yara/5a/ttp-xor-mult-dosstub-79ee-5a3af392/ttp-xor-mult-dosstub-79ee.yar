rule TTP_XOR_MULT_DOSStub_79ee {
  strings:
    $key_79ee = { 2d 86 [2] 59 9e [2] 1e 9c [2] 59 8d [2] 17 81 [2] 1b 8b [2] 0c 80 [2] 17 ce [2] 2a }

  condition:
    any of them
}