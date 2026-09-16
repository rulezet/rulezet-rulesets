rule TTP_XOR_MULT_DOSStub_7bee {
  strings:
    $key_7bee = { 2f 86 [2] 5b 9e [2] 1c 9c [2] 5b 8d [2] 15 81 [2] 19 8b [2] 0e 80 [2] 15 ce [2] 28 }

  condition:
    any of them
}